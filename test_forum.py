import os
import re
from pathlib import Path
import tempfile

os.environ['FORUM_DB'] = str(Path(tempfile.mkdtemp(prefix='defendeu_test_'))/'forum.sqlite3')
os.environ['FORUM_SECRET_KEY']='test-only-secret-not-for-production-XXXXXXXXXXXXXXXXXXXXXXXXX'
os.environ['FORUM_ADMIN_USERNAME']='moderator_test'
os.environ['FORUM_ADMIN_PASSWORD']='Very-long-test-passphrase-123'

from fastapi.testclient import TestClient
from app import app

client=TestClient(app,follow_redirects=True)

def token(response):
    return re.search(r'name="csrf" value="([^\"]+)"', response.text).group(1)


def test_conversations_and_moderation():
    r=client.get('/'); assert r.status_code==200 and 'Safe' in r.text
    r=client.get('/register'); c=token(r)
    r=client.post('/register',data={'csrf':c,'username':'TestMember42','password':'passphrase-for-member','agree':'yes'})
    assert r.status_code==200 and 'Welcome to the community' in r.text
    r=client.get('/new'); c=token(r); assert r.status_code==200
    r=client.post('/new',data={'csrf':c,'title':'How do I protect my accounts?','category_id':'3','body':'I would like to understand two-factor authentication.'})
    assert r.status_code==200 and 'How do I protect my accounts?' in r.text
    match=re.search(r'/topic/(\d+)',r.url.path)
    assert match
    tid=match.group(1)
    c=token(r)
    r=client.post(f'/topic/{tid}/reply',data={'csrf':c,'body':'Use a unique passphrase for each account.'})
    assert r.status_code==200 and 'Use a unique passphrase' in r.text
    c=token(r)
    r=client.post('/report',data={'csrf':c,'thread_id':tid,'reason':'Spam'})
    assert r.status_code==200 and 'moderator can review' in r.text
    r=client.get('/'); c=token(r)
    r=client.post('/logout',data={'csrf':c}); assert r.status_code==200
    r=client.get('/login'); c=token(r)
    r=client.post('/login',data={'csrf':c,'username':'moderator_test','password':'Very-long-test-passphrase-123'})
    assert r.status_code==200
    r=client.get('/moderation'); assert r.status_code==200 and 'Spam' in r.text
    c=token(r)
    r=client.post(f'/moderation/thread/{tid}',data={'csrf':c,'action':'hide'})
    assert r.status_code==200 and 'hidden from the public' in r.text
    assert client.get('/healthz').text == 'OK'

if __name__=='__main__':
    test_conversations_and_moderation()
    print('OK: register/login, thread, reply, report, moderation, health')
