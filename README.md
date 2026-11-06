# DefendEUrself Community Forum

**This repository is the independent DefendEUrself Community Forum website.**
It is **not** the primary DefendEUrself project website.

This is a real Python-powered forum (accounts, topics, replies, search, categories, reports and moderation). It requires a dynamic hosting service: **GitHub Pages cannot run Python, SQLite or logins.**

The GitHub repository files are intentionally placed at the root, to match the existing repository layout. The frontend uses `home.html`, `topic.html`, `styles.css`, etc.; the app itself serves the forum at `/` once deployed. Opening README on GitHub will **never show the forum**.

To publish, use a Python/Docker host such as Railway, configure secrets, attach a **persistent volume** at `/app/data`, set `FORUM_DB=/app/data/forum.sqlite3` and `FORUM_SECURE_COOKIES=1`, and generate an HTTPS domain. The web app runs via `Dockerfile` and has a `/healthz` check.

For step-by-step guidance in Italian see `LEGGIMI_PRIMA.txt`.

Public launch still needs appropriate GDPR notices, content moderation responsibilities, backups and a security review.
