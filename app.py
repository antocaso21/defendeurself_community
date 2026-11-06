"""DefendEUrself Community Forum — small self-hosted FastAPI + SQLite forum.

Run: uvicorn app:app --reload (from this directory).
No fake public data is seeded. Account emails are not collected.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, FileResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).parent
DB_FILE = Path(os.environ.get("FORUM_DB", str(ROOT / "data" / "forum.sqlite3")))
DB_FILE.parent.mkdir(parents=True, exist_ok=True)
SECRET_KEY = os.getenv("FORUM_SECRET_KEY") or secrets.token_hex(32)
SECURE_COOKIES = os.getenv("FORUM_SECURE_COOKIES", "0") == "1"
SITE_URL = os.getenv("PROJECT_SITE_URL", "https://www.defendeurself.eu/")
BASE_PATH = os.getenv("FORUM_BASE_PATH", "").rstrip("/")

app = FastAPI(title="DefendEUrself Community Forum", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=SECURE_COOKIES, max_age=60*60*24*14)
# GitHub-upload friendly: site templates, stylesheet and JS live at the repository root.
# Serve only the two public assets; never expose app.py, environment files or the database.
templates = Jinja2Templates(directory=str(ROOT))

@app.get("/static/styles.css", include_in_schema=False)
def style_asset():
    return FileResponse(ROOT / "styles.css", media_type="text/css")

@app.get("/static/main.js", include_in_schema=False)
def script_asset():
    return FileResponse(ROOT / "main.js", media_type="text/javascript")

CATEGORIES = [
    ("getting-started", "Getting started", "Introduce yourself and ask questions about using the forum.", "👋"),
    ("scams", "Scams & suspicious messages", "Recognise phishing, fake messages and suspicious links.", "🛡️"),
    ("passwords", "Passwords & authentication", "Safer passwords, passphrases and two-factor authentication.", "🔑"),
    ("banking", "Online banking & shopping", "Learn safe habits for purchases, payments and banking.", "💳"),
    ("privacy", "Privacy & personal data", "Protect your information and understand digital footprints.", "🔒"),
    ("social-media", "Social media safety", "Safer sharing and communication on social networks.", "💬"),
    ("training", "Micro-MOOCs & learning", "Discuss DefendEUrself training materials and exercises.", "🎓"),
    ("educators", "Educators' corner", "Exchange teaching ideas and accessible learning practices.", "🤝"),
]

@contextmanager
def connection():
    conn = sqlite3.connect(str(DB_FILE), timeout=12)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=12000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize():
    with connection() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS categories (
          id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE,
          title TEXT NOT NULL, description TEXT NOT NULL, icon TEXT NOT NULL,
          position INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS threads (
          id INTEGER PRIMARY KEY, category_id INTEGER NOT NULL REFERENCES categories(id),
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, body TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          is_hidden INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS replies (
          id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          is_hidden INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reports (
          id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          thread_id INTEGER REFERENCES threads(id) ON DELETE CASCADE,
          reply_id INTEGER REFERENCES replies(id) ON DELETE CASCADE,
          reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CHECK ((thread_id IS NULL) != (reply_id IS NULL))
        );
        CREATE INDEX IF NOT EXISTS idx_threads_recent ON threads(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_threads_category ON threads(category_id);
        CREATE INDEX IF NOT EXISTS idx_replies_thread ON replies(thread_id);
        """)
        for i, (slug, title, description, icon) in enumerate(CATEGORIES):
            db.execute("INSERT OR IGNORE INTO categories(slug,title,description,icon,position) VALUES(?,?,?,?,?)",
                       (slug,title,description,icon,i))
        admin_user = os.environ.get("FORUM_ADMIN_USERNAME", "")
        admin_password = os.environ.get("FORUM_ADMIN_PASSWORD", "")
        if admin_user and admin_password and len(admin_password) >= 12 and valid_username(admin_user):
            existing = db.execute("SELECT id,role FROM users WHERE username=?", (admin_user,)).fetchone()
            if not existing:
                db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                           (admin_user, encode_password(admin_password), "admin"))
            elif existing["role"] != "admin":
                # Do not silently promote an existing untrusted account.
                print("ADMIN WARNING: requested admin username exists as member; no promotion made")


def valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{3,24}", username))


def encode_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 450_000)
    return f"pbkdf2_sha256$450000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, count, salt, hexdigest = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(count))
        return hmac.compare_digest(digest, bytes.fromhex(hexdigest))
    except (ValueError, TypeError):
        return False

initialize()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def logged_user(request: Request):
    uid = request.session.get("uid")
    if not isinstance(uid,int):
        return None
    with connection() as db:
        row = db.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None


def csrf_token(request: Request):
    if not request.session.get("csrf"):
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]


def check_csrf(request: Request, token: str):
    expected = request.session.get("csrf", "")
    if not expected or not hmac.compare_digest(expected, token):
        raise HTTPException(status_code=403, detail="Invalid form token. Reload the page and try again.")

# In-memory throttle is an additional safeguard, not a substitute for reverse proxy limits.
_ATTEMPTS = {}
def throttle(request: Request, action: str, limit: int, window_s: int):
    ip = request.client.host if request.client else "unknown"
    key = (ip, action)
    now = time.monotonic()
    recent = [x for x in _ATTEMPTS.get(key, []) if now - x < window_s]
    if len(recent) >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
    recent.append(now)
    _ATTEMPTS[key] = recent


def render(request: Request, name: str, **context):
    return templates.TemplateResponse(request=request, name=name, context={
        "user": logged_user(request), "csrf": csrf_token(request),
        "site_url": SITE_URL, "base_path": BASE_PATH, "notice": request.query_params.get("notice", ""),
        **context,
    })


def must_login(request: Request):
    user = logged_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in to continue.")
    return user


def must_admin(request: Request):
    user = must_login(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Moderators only.")
    return user


def clean(s: str) -> str:
    return s.strip().replace("\x00", "")


def redirect(url: str):
    return RedirectResponse(url=(BASE_PATH + url if url.startswith("/") else url), status_code=303)


@app.get("/healthz", response_class=PlainTextResponse)
def health():
    with connection() as db:
        db.execute("SELECT 1").fetchone()
    return "OK"


@app.get("/", response_class=HTMLResponse)
def home(request: Request, q: str = "", category: str = "", sort: str = "active"):
    q = clean(q)[:100]
    with connection() as db:
        cats = [dict(x) for x in db.execute("""
          SELECT c.*, COUNT(t.id) AS count FROM categories c
          LEFT JOIN threads t ON t.category_id=c.id AND t.is_hidden=0
          GROUP BY c.id ORDER BY c.position
        """).fetchall()]
        filters = ["t.is_hidden=0"]
        params = []
        if category:
            filters.append("c.slug=?")
            params.append(category)
        if q:
            filters.append("(t.title LIKE ? OR t.body LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        order = "t.created_at DESC" if sort == "newest" else "t.updated_at DESC"
        sql = f"""SELECT t.id,t.title,t.body,t.created_at,t.updated_at,c.title AS category_title,
           c.slug AS category_slug,c.icon AS category_icon,u.username,
           (SELECT COUNT(*) FROM replies r WHERE r.thread_id=t.id AND r.is_hidden=0) AS reply_count
           FROM threads t JOIN categories c ON c.id=t.category_id
           JOIN users u ON u.id=t.user_id WHERE {' AND '.join(filters)} ORDER BY {order} LIMIT 100"""
        threads = [dict(x) for x in db.execute(sql,params).fetchall()]
    return render(request,"home.html",categories=cats,threads=threads,q=q,category=category,sort=sort)


@app.get("/category/{slug}", response_class=HTMLResponse)
def category_page(slug: str):
    return redirect("/?category="+slug)


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return render(request,"auth.html",mode="register",error=None)


@app.post("/register")
def register(request: Request, username: str=Form(...), password: str=Form(...),
             agree: str=Form(""), csrf: str=Form(...)):
    check_csrf(request,csrf)
    throttle(request, "register", 5, 3600)
    username = clean(username)
    if not valid_username(username) or not 10 <= len(password) <= 200 or agree != "yes":
        return render(request,"auth.html",mode="register",error="Use 3–24 letters/numbers for your username, a password of at least 10 characters, and accept the community rules.")
    with connection() as db:
        try:
            cur=db.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",(username,encode_password(password)))
        except sqlite3.IntegrityError:
            return render(request,"auth.html",mode="register",error="This username is already taken.")
        request.session.clear()
        request.session["uid"] = cur.lastrowid
        request.session["csrf"] = secrets.token_urlsafe(32)
    return redirect("/?notice=welcome")


@app.get("/login",response_class=HTMLResponse)
def login_form(request: Request):
    return render(request,"auth.html",mode="login",error=None)


@app.post("/login")
def login(request: Request,username: str=Form(...),password: str=Form(...),csrf: str=Form(...)):
    check_csrf(request,csrf)
    throttle(request,"login",12,900)
    with connection() as db:
        row=db.execute("SELECT id,password_hash FROM users WHERE username=?",(clean(username),)).fetchone()
    if row is None or not verify_password(password,row["password_hash"]):
        return render(request,"auth.html",mode="login",error="Username or password not recognised.")
    request.session.clear()
    request.session["uid"] = row["id"]
    request.session["csrf"] = secrets.token_urlsafe(32)
    return redirect("/?notice=loggedin")


@app.post("/logout")
def logout(request: Request,csrf:str=Form(...)):
    check_csrf(request,csrf)
    request.session.clear()
    return redirect("/")


@app.get("/new",response_class=HTMLResponse)
def create_form(request: Request):
    if not logged_user(request):
        return redirect("/login")
    with connection() as db:
        categories=[dict(x) for x in db.execute("SELECT * FROM categories ORDER BY position")]
    return render(request,"new.html",categories=categories,error=None)


@app.post("/new")
def create_thread(request: Request,title: str=Form(...),body: str=Form(...),category_id: int=Form(...),csrf:str=Form(...)):
    user=must_login(request)
    check_csrf(request,csrf)
    throttle(request,"post",8,3600)
    title, body=clean(title),clean(body)
    if not (6<=len(title)<=140 and 15<=len(body)<=5000):
        with connection() as db:
            categories=[dict(x) for x in db.execute("SELECT * FROM categories ORDER BY position")]
        return render(request,"new.html",categories=categories,error="Please write a title (6–140 characters) and a message (15–5000 characters).")
    with connection() as db:
        if not db.execute("SELECT 1 FROM categories WHERE id=?", (category_id,)).fetchone():
            raise HTTPException(400,"Invalid category")
        cur=db.execute("INSERT INTO threads(category_id,user_id,title,body) VALUES(?,?,?,?)",
                       (category_id,user["id"],title,body))
        new_id=cur.lastrowid
    return redirect(f"/topic/{new_id}?notice=posted")


@app.get("/topic/{thread_id}",response_class=HTMLResponse)
def topic(request: Request,thread_id:int):
    user=logged_user(request)
    with connection() as db:
        row=db.execute("""SELECT t.*,c.title AS category_title,c.slug AS category_slug,
            c.icon AS category_icon,u.username FROM threads t
            JOIN categories c ON c.id=t.category_id JOIN users u ON u.id=t.user_id
            WHERE t.id=?""",(thread_id,)).fetchone()
        if row is None or (row["is_hidden"] and not (user and user["role"]=="admin")):
            raise HTTPException(404,"Discussion unavailable")
        replies=[dict(x) for x in db.execute("""SELECT r.*,u.username FROM replies r JOIN users u
          ON r.user_id=u.id WHERE r.thread_id=? AND (r.is_hidden=0 OR ?=1) ORDER BY r.created_at,r.id""",
          (thread_id,int(bool(user and user["role"]=="admin")))).fetchall()]
    return render(request,"topic.html",thread=dict(row),replies=replies)


@app.post("/topic/{thread_id}/reply")
def reply(request: Request,thread_id: int,body: str=Form(...),csrf:str=Form(...)):
    user=must_login(request)
    check_csrf(request,csrf)
    throttle(request,"reply",25,3600)
    body=clean(body)
    if not 2<=len(body)<=3000:
        raise HTTPException(400,"Reply must be 2–3000 characters")
    with connection() as db:
        row=db.execute("SELECT id FROM threads WHERE id=? AND is_hidden=0",(thread_id,)).fetchone()
        if not row:
            raise HTTPException(404,"Discussion unavailable")
        db.execute("INSERT INTO replies(thread_id,user_id,body) VALUES(?,?,?)",(thread_id,user["id"],body))
        db.execute("UPDATE threads SET updated_at=CURRENT_TIMESTAMP WHERE id=?",(thread_id,))
    return redirect(f"/topic/{thread_id}?notice=replied#replies")


@app.post("/report")
def report(request: Request,thread_id: int=Form(0),reply_id: int=Form(0),
           reason:str=Form(...),csrf:str=Form(...)):
    user=must_login(request)
    check_csrf(request,csrf)
    throttle(request,"report",12,3600)
    if reason not in ("Suspected scam","Personal data exposed","Harassment","Spam","Other"):
        raise HTTPException(400,"Please choose a reason")
    if bool(thread_id) == bool(reply_id):
        raise HTTPException(400,"Report one item")
    with connection() as db:
        if thread_id:
            row=db.execute("SELECT id FROM threads WHERE id=?",(thread_id,)).fetchone()
            back=thread_id
        else:
            row=db.execute("SELECT thread_id FROM replies WHERE id=?",(reply_id,)).fetchone()
            back=row["thread_id"] if row else 0
        if not row:
            raise HTTPException(404,"Content not found")
        db.execute("INSERT INTO reports(reporter_id,thread_id,reply_id,reason) VALUES(?,?,?,?)",
                   (user["id"],thread_id or None,reply_id or None,reason))
    return redirect(f"/topic/{back}?notice=reported")


@app.get("/moderation",response_class=HTMLResponse)
def moderation(request: Request):
    must_admin(request)
    with connection() as db:
        reports=[dict(x) for x in db.execute("""SELECT r.*,u.username AS reporter,
          COALESCE(r.thread_id,t.thread_id) AS context_id
          FROM reports r JOIN users u ON r.reporter_id=u.id
          LEFT JOIN replies t ON r.reply_id=t.id
          WHERE r.status='open' ORDER BY r.created_at DESC LIMIT 100""").fetchall()]
    return render(request,"moderation.html",reports=reports)


@app.post("/moderation/{kind}/{item_id}")
def moderate(request: Request,kind:str,item_id:int,action:str=Form(...),csrf:str=Form(...)):
    must_admin(request)
    check_csrf(request,csrf)
    if kind not in ("thread","reply","report") or action not in ("hide","show","resolve"):
        raise HTTPException(400,"Invalid moderation action")
    with connection() as db:
        if kind=="thread" and action in ("hide","show"):
            db.execute("UPDATE threads SET is_hidden=? WHERE id=?",(int(action=="hide"),item_id))
        elif kind=="reply" and action in ("hide","show"):
            db.execute("UPDATE replies SET is_hidden=? WHERE id=?",(int(action=="hide"),item_id))
        elif kind=="report" and action=="resolve":
            db.execute("UPDATE reports SET status='resolved' WHERE id=?",(item_id,))
        else:
            raise HTTPException(400,"Invalid moderation action")
    return redirect("/moderation?notice=moderated" if kind=="report" else f"/topic/{item_id}" if kind=="thread" else "/moderation?notice=moderated")


@app.get("/guidelines",response_class=HTMLResponse)
def guidelines(request:Request):
    return render(request,"guidelines.html")


@app.get("/account",response_class=HTMLResponse)
def account(request:Request):
    user=logged_user(request)
    if not user:
        return redirect("/login")
    return render(request,"account.html",error=None)


@app.post("/account/delete")
def delete_account(request:Request,password:str=Form(...),csrf:str=Form(...)):
    user=must_login(request)
    check_csrf(request,csrf)
    with connection() as db:
        row=db.execute("SELECT password_hash,role FROM users WHERE id=?",(user["id"],)).fetchone()
        if not row or not verify_password(password,row["password_hash"]):
            return render(request,"account.html",error="Password incorrect.")
        if row["role"]=="admin":
            return render(request,"account.html",error="An administrator account must be removed by the server operator.")
        db.execute("DELETE FROM users WHERE id=?",(user["id"],))
    request.session.clear()
    return redirect("/?notice=deleted")
