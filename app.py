import sqlite3, hashlib, secrets, time, mimetypes, os, json, re
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from functools import wraps
from flask import Flask, request, session, jsonify, send_file, g, render_template, abort
from cryptography.fernet import Fernet

BASE = Path(__file__).parent
DATA = BASE / 'data'
DATA.mkdir(exist_ok=True)
AVATARS = DATA / 'avatars'; AVATARS.mkdir(exist_ok=True)
FILES = DATA / 'files'; FILES.mkdir(exist_ok=True)

KEY_FILE = DATA / 'secret.key'
if not KEY_FILE.exists(): KEY_FILE.write_bytes(Fernet.generate_key())
FERNET = Fernet(KEY_FILE.read_bytes())

SESS_FILE = DATA / 'session.key'
if not SESS_FILE.exists(): SESS_FILE.write_bytes(secrets.token_bytes(32))

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = SESS_FILE.read_bytes()
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

APP_VERSION = '2.3'

@app.after_request
def no_cache(resp):
    p = request.path or ''
    if p.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    elif p.endswith('.html') or p == '/' or p.startswith('/static/'):
        resp.headers['Cache-Control'] = 'no-cache, must-revalidate, max-age=0'
    return resp

DB = DATA / 'messenger.db'
DEV_USERNAME, DEV_PASSWORD, DEV_NAME = 'stepan', 'gtfdes1M#', 'Степан'
ONLINE_WINDOW = 60
TYPING_WINDOW = 5
REACTIONS = ['👍','❤️','😂','🔥','😢','😮']

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def _close(e=None):
    d = g.pop('db', None)
    if d: d.close()

def has_col(con, t, c):
    return c in [r[1] for r in con.execute(f'PRAGMA table_info({t})').fetchall()]

def add_col(con, t, c, decl):
    if not has_col(con, t, c):
        con.execute(f'ALTER TABLE {t} ADD COLUMN {c} {decl}')

def init_db():
    con = sqlite3.connect(DB)
    try:
        con.execute('DROP TABLE IF EXISTS typing'); con.commit()
    except Exception: pass
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL, pw_hash BLOB NOT NULL, salt BLOB NOT NULL,
      avatar TEXT, is_dev INTEGER DEFAULT 0, banned INTEGER DEFAULT 0,
      status TEXT DEFAULT 'online', last_seen REAL DEFAULT 0,
      bio TEXT DEFAULT '', created REAL);
    CREATE TABLE IF NOT EXISTS chats(
      id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, name TEXT,
      owner_id INTEGER, avatar TEXT, description TEXT DEFAULT '',
      invite_hash TEXT, slow_mode INTEGER DEFAULT 0,
      comments_chat_id INTEGER DEFAULT NULL,
      is_secret INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS members(
      chat_id INTEGER, user_id INTEGER, is_admin INTEGER DEFAULT 0,
      can_send INTEGER DEFAULT 1, can_invite INTEGER DEFAULT 0,
      can_pin INTEGER DEFAULT 0, can_delete INTEGER DEFAULT 0,
      joined REAL, PRIMARY KEY(chat_id,user_id));
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL, text BLOB, file_id INTEGER,
      is_sticker INTEGER DEFAULT 0, is_voice INTEGER DEFAULT 0,
      duration REAL DEFAULT 0, deleted INTEGER DEFAULT 0,
      reply_to INTEGER DEFAULT NULL, edited INTEGER DEFAULT 0,
      poll_id INTEGER DEFAULT NULL, enc INTEGER DEFAULT 0,
      created REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS files(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, mime TEXT,
      size INTEGER, path TEXT);
    CREATE TABLE IF NOT EXISTS blocks(
      user_id INTEGER, blocked_id INTEGER, created REAL,
      PRIMARY KEY(user_id, blocked_id));
    CREATE TABLE IF NOT EXISTS hidden_chats(
      user_id INTEGER, chat_id INTEGER, hidden_at REAL,
      PRIMARY KEY(user_id, chat_id));
    CREATE TABLE IF NOT EXISTS wallpapers(
      user_id INTEGER, chat_id INTEGER, value TEXT,
      PRIMARY KEY(user_id, chat_id));
    CREATE TABLE IF NOT EXISTS sticker_packs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER,
      name TEXT NOT NULL, is_official INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS pack_stickers(
      id INTEGER PRIMARY KEY AUTOINCREMENT, pack_id INTEGER,
      file_id INTEGER, created REAL);
    CREATE TABLE IF NOT EXISTS reactions(
      message_id INTEGER, user_id INTEGER, emoji TEXT,
      PRIMARY KEY(message_id, user_id, emoji));
    CREATE TABLE IF NOT EXISTS typing(
      user_id INTEGER, chat_id INTEGER, ts REAL,
      PRIMARY KEY(user_id, chat_id));
    CREATE TABLE IF NOT EXISTS pinned(
      chat_id INTEGER, message_id INTEGER, pinned_by INTEGER, pinned_at REAL,
      PRIMARY KEY(chat_id, message_id));
    CREATE TABLE IF NOT EXISTS folders(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
      name TEXT NOT NULL, position INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS folder_chats(
      folder_id INTEGER, chat_id INTEGER, PRIMARY KEY(folder_id, chat_id));
    CREATE TABLE IF NOT EXISTS polls(
      id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER,
      question TEXT, options TEXT, multiple INTEGER DEFAULT 0,
      anonymous INTEGER DEFAULT 0, closes_at REAL DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS poll_votes(
      poll_id INTEGER, user_id INTEGER, option_idx INTEGER,
      PRIMARY KEY(poll_id, user_id, option_idx));
    CREATE TABLE IF NOT EXISTS calls(
      id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER,
      caller_id INTEGER, callee_id INTEGER, kind TEXT,
      state TEXT DEFAULT 'ringing',
      offer TEXT, answer TEXT,
      caller_ice TEXT, callee_ice TEXT,
      created REAL, updated REAL);
    CREATE TABLE IF NOT EXISTS secret_keys(
      chat_id INTEGER, user_id INTEGER, wrapped TEXT,
      PRIMARY KEY(chat_id, user_id));
    ''')
    con.commit()

    add_col(con, 'users', 'bio', "TEXT DEFAULT ''")
    add_col(con, 'users', 'banned', 'INTEGER DEFAULT 0')
    add_col(con, 'users', 'status', "TEXT DEFAULT 'online'")
    add_col(con, 'users', 'last_seen', 'REAL DEFAULT 0')
    for c in ('is_sticker','is_voice'):
        add_col(con, 'messages', c, 'INTEGER DEFAULT 0')
    add_col(con, 'messages', 'duration', 'REAL DEFAULT 0')
    add_col(con, 'messages', 'deleted', 'INTEGER DEFAULT 0')
    add_col(con, 'messages', 'reply_to', 'INTEGER DEFAULT NULL')
    add_col(con, 'messages', 'edited', 'INTEGER DEFAULT 0')
    add_col(con, 'messages', 'poll_id', 'INTEGER DEFAULT NULL')
    add_col(con, 'messages', 'enc', 'INTEGER DEFAULT 0')
    add_col(con, 'chats', 'description', "TEXT DEFAULT ''")
    add_col(con, 'chats', 'invite_hash', 'TEXT')
    add_col(con, 'chats', 'slow_mode', 'INTEGER DEFAULT 0')
    add_col(con, 'chats', 'comments_chat_id', 'INTEGER DEFAULT NULL')
    add_col(con, 'chats', 'is_secret', 'INTEGER DEFAULT 0')
    for c in ('is_admin','can_invite','can_pin','can_delete'):
        add_col(con, 'members', c, 'INTEGER DEFAULT 0')
    add_col(con, 'members', 'can_send', 'INTEGER DEFAULT 1')
    add_col(con, 'members', 'joined', 'REAL DEFAULT 0')
    con.commit()

    for r in con.execute("SELECT id FROM chats WHERE type IN ('group','channel') AND (invite_hash IS NULL OR invite_hash='')").fetchall():
        con.execute('UPDATE chats SET invite_hash=? WHERE id=?', (secrets.token_urlsafe(10), r[0]))
    con.commit()

    try:
        old = con.execute('SELECT COUNT(*) FROM stickers').fetchone()[0]
    except sqlite3.OperationalError: old = 0
    if old:
        rows = con.execute('SELECT user_id, file_id FROM stickers ORDER BY user_id, id').fetchall()
        byu = defaultdict(list)
        for uid, fid in rows: byu[uid].append(fid)
        for uid, files in byu.items():
            ex = con.execute("SELECT id FROM sticker_packs WHERE owner_id=? AND name='Мои стикеры' LIMIT 1", (uid,)).fetchone()
            pid = ex[0] if ex else con.execute(
                "INSERT INTO sticker_packs(owner_id,name,is_official,created) VALUES(?,?,0,?)",
                (uid, 'Мои стикеры', time.time())).lastrowid
            for fid in files:
                con.execute('INSERT INTO pack_stickers(pack_id,file_id,created) VALUES(?,?,?)',
                            (pid, fid, time.time()))
        con.execute('DROP TABLE stickers'); con.commit()

    if not con.execute('SELECT 1 FROM users WHERE username=?', (DEV_USERNAME,)).fetchone():
        salt = secrets.token_bytes(16)
        h = hashlib.pbkdf2_hmac('sha256', DEV_PASSWORD.encode(), salt, 200000)
        con.execute('INSERT INTO users(name,username,pw_hash,salt,is_dev,created) VALUES(?,?,?,?,1,?)',
                    (DEV_NAME, DEV_USERNAME, h, salt, time.time()))
        con.commit()
    con.close()

init_db()

def hash_pw(pw, salt=None):
    if salt is None: salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, 200000), salt

def user_status(u):
    if not u: return 'recently'
    if u['status'] == 'dnd': return 'dnd'
    ls = u['last_seen'] or 0
    if time.time() - ls < ONLINE_WINDOW: return 'online'
    return 'recently'

def user_json(u):
    if not u: return None
    d = {'id':u['id'],'name':u['name'],'username':u['username'],
         'avatar':u['avatar'],'is_dev':bool(u['is_dev']),
         'status': u['status'] if u['status'] in ('online','recently','dnd') else 'recently',
         'online': user_status(u) == 'online',
         'last_seen': u['last_seen'] or 0}
    try: d['bio'] = u['bio'] or ''
    except Exception: d['bio'] = ''
    return d

def member_json(r):
    return {'user_id': r['user_id'], 'is_admin': bool(r['is_admin']),
            'can_send': bool(r['can_send']), 'can_invite': bool(r['can_invite']),
            'can_pin': bool(r['can_pin']), 'can_delete': bool(r['can_delete'])}

def me():
    uid = session.get('uid')
    if not uid: return None
    db = get_db()
    u = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if u:
        db.execute('UPDATE users SET last_seen=? WHERE id=?', (time.time(), uid)); db.commit()
        u = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    return u

def my_membership(db, cid):
    u = me()
    if not u: return None
    return db.execute('SELECT * FROM members WHERE chat_id=? AND user_id=?', (cid, u['id'])).fetchone()

def is_dev_local():
    u = me()
    if not u or not u['is_dev']: return False
    addr = request.remote_addr or ''
    host = (request.host or '').split(':')[0]
    return addr in ('127.0.0.1','::1') or host in ('127.0.0.1','localhost','[::1]')

def auth(f):
    @wraps(f)
    def w(*a, **k):
        if not me(): return jsonify(error='unauthorized'), 401
        return f(*a, **k)
    return w

def decrypt_text(b):
    if not b: return ''
    try: return FERNET.decrypt(b).decode('utf-8','replace')
    except Exception: return ''

def can_post(db, c, mship):
    if not mship: return False
    if c['type'] == 'channel':
        return bool(mship['is_admin'])
    if not mship['can_send'] and not mship['is_admin']: return False
    return True

def build_poll(db, poll_id, viewer_id):
    p = db.execute('SELECT * FROM polls WHERE id=?', (poll_id,)).fetchone()
    if not p: return None
    options = json.loads(p['options'])
    votes = db.execute('SELECT user_id, option_idx FROM poll_votes WHERE poll_id=?', (poll_id,)).fetchall()
    counts = [0]*len(options); mine = []
    voters = defaultdict(list)
    for v in votes:
        counts[v['option_idx']] += 1
        voters[v['option_idx']].append(v['user_id'])
        if v['user_id'] == viewer_id: mine.append(v['option_idx'])
    closed = p['closes_at'] and time.time() > p['closes_at']
    return {'id': p['id'], 'question': p['question'], 'options': options,
            'counts': counts, 'multiple': bool(p['multiple']),
            'anonymous': bool(p['anonymous']), 'closes_at': p['closes_at'],
            'closed': bool(closed), 'my_votes': mine,
            'total': sum(counts)}

def build_message(db, r, viewer_id=None, blocked_ids=None):
    if blocked_ids and r['sender_id'] in blocked_ids: return None
    s = db.execute('SELECT * FROM users WHERE id=?', (r['sender_id'],)).fetchone()
    if r['deleted']:
        return {'id': r['id'], 'sender': user_json(s), 'text': '', 'file': None,
                'is_sticker': False, 'is_voice': False, 'duration': 0,
                'deleted': True, 'edited': False, 'reply_to': None,
                'reactions': [], 'created': r['created'], 'poll': None, 'enc': False}
    txt = decrypt_text(r['text'])
    f = None
    if r['file_id']:
        fr = db.execute('SELECT * FROM files WHERE id=?', (r['file_id'],)).fetchone()
        if fr: f = {'id': fr['id'], 'name': fr['name'], 'mime': fr['mime'], 'size': fr['size']}
    reply = None
    if r['reply_to']:
        rr = db.execute('SELECT * FROM messages WHERE id=?', (r['reply_to'],)).fetchone()
        if rr:
            rs = db.execute('SELECT name FROM users WHERE id=?', (rr['sender_id'],)).fetchone()
            reply = {'id': rr['id'], 'sender': rs['name'] if rs else '?',
                     'text': decrypt_text(rr['text'])[:100],
                     'is_sticker': bool(rr['is_sticker']),
                     'is_voice': bool(rr['is_voice']),
                     'file': bool(rr['file_id']),
                     'deleted': bool(rr['deleted'])}
    poll = None
    if r['poll_id']:
        poll = build_poll(db, r['poll_id'], viewer_id)
    return {'id': r['id'], 'sender': user_json(s), 'text': txt, 'file': f,
            'is_sticker': bool(r['is_sticker']), 'is_voice': bool(r['is_voice']),
            'duration': r['duration'] or 0, 'deleted': False,
            'edited': bool(r['edited']), 'reply_to': reply,
            'reactions': [], 'created': r['created'], 'poll': poll,
            'enc': bool(r['enc'])}

def attach_reactions(db, msgs):
    if not msgs: return msgs
    ids = [m['id'] for m in msgs]
    ph = ','.join(['?']*len(ids))
    rows = db.execute(f'SELECT message_id, user_id, emoji FROM reactions WHERE message_id IN ({ph})', ids).fetchall()
    grouped = defaultdict(lambda: defaultdict(list))
    for r in rows: grouped[r['message_id']][r['emoji']].append(r['user_id'])
    by_id = {m['id']: m for m in msgs}
    for mid, emojis in grouped.items():
        if mid in by_id:
            by_id[mid]['reactions'] = [{'emoji': e, 'count': len(us), 'user_ids': us} for e, us in emojis.items()]
    return msgs

@app.get('/')
def index(): return render_template('index.html')

@app.get('/j/<invite>')
def invite_page(invite): return render_template('index.html')

@app.get('/favicon.ico')
def favicon(): return send_file(BASE/'static'/'icon.svg', mimetype='image/svg+xml')

@app.get('/api/version')
def version(): return jsonify(version=APP_VERSION)

# ---------- AUTH ----------
@app.get('/api/check_username')
@auth
def check_username():
    u = (request.args.get('u') or '').strip().lstrip('@').lower()
    cur = request.args.get('current') or ''
    db = get_db()
    if len(u) < 3: return jsonify(available=False, reason='минимум 3 символа')
    if not re.match(r'^[a-z0-9_]+$', u): return jsonify(available=False, reason='только a-z, 0-9, _')
    if u == (cur or '').lower(): return jsonify(available=True, reason='ваш текущий')
    ex = db.execute('SELECT 1 FROM users WHERE username=?', (u,)).fetchone()
    return jsonify(available=not ex, reason='занят' if ex else 'свободен')

@app.post('/api/register')
def register():
    d = request.get_json(force=True) or {}
    name = (d.get('name') or '').strip()
    username = (d.get('username') or '').strip().lstrip('@').lower()
    password = d.get('password') or ''
    if not name or not username or not password: return jsonify(error='Заполните все поля'), 400
    if len(username) < 3 or not re.match(r'^[a-z0-9_]+$', username):
        return jsonify(error='Юзернейм: 3+ символа (a-z, 0-9, _)'), 400
    if len(name) > 40: return jsonify(error='Слишком длинное имя'), 400
    if len(password) < 6: return jsonify(error='Пароль минимум 6 символов'), 400
    db = get_db()
    if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
        return jsonify(error='Юзернейм занят'), 400
    h, s = hash_pw(password)
    cur = db.execute('INSERT INTO users(name,username,pw_hash,salt,status,last_seen,created) VALUES(?,?,?,?,?,?,?)',
                     (name, username, h, s, 'online', time.time(), time.time()))
    db.commit(); session['uid'] = cur.lastrowid
    return jsonify(ok=True)

@app.post('/api/login')
def login():
    d = request.get_json(force=True) or {}
    username = (d.get('username') or '').strip().lstrip('@').lower()
    password = d.get('password') or ''
    db = get_db()
    u = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not u: return jsonify(error='Неверный логин или пароль'), 401
    h, _ = hash_pw(password, u['salt'])
    if not secrets.compare_digest(h, u['pw_hash']): return jsonify(error='Неверный логин или пароль'), 401
    if u['banned']: return jsonify(error='Аккаунт заблокирован'), 403
    db.execute('UPDATE users SET last_seen=? WHERE id=?', (time.time(), u['id'])); db.commit()
    session['uid'] = u['id']
    return jsonify(ok=True)

@app.post('/api/logout')
def logout():
    uid = session.get('uid')
    if uid:
        db = get_db(); db.execute('UPDATE users SET last_seen=0 WHERE id=?', (uid,)); db.commit()
    session.clear(); return jsonify(ok=True)

@app.get('/api/me')
@auth
def get_me():
    j = user_json(me()); j['is_dev_local'] = is_dev_local(); j['app_version'] = APP_VERSION
    return jsonify(j)

@app.post('/api/me/status')
@auth
def set_status():
    d = request.get_json(force=True) or {}
    s = d.get('status')
    if s not in ('online','recently','dnd'): return jsonify(error='Неверный статус'), 400
    db = get_db(); u = me()
    db.execute('UPDATE users SET status=? WHERE id=?', (s, u['id'])); db.commit()
    return jsonify(ok=True)

@app.patch('/api/me')
@auth
def update_me():
    d = request.get_json(force=True) or {}
    db = get_db(); u = me()
    if 'name' in d:
        name = (d.get('name') or '').strip()
        if not name or len(name) > 40: return jsonify(error='Некорректное имя'), 400
        db.execute('UPDATE users SET name=? WHERE id=?', (name, u['id']))
    if 'username' in d:
        username = (d.get('username') or '').strip().lstrip('@').lower()
        if len(username) < 3 or not re.match(r'^[a-z0-9_]+$', username):
            return jsonify(error='Юзернейм: 3+ символа'), 400
        if db.execute('SELECT 1 FROM users WHERE username=? AND id!=?', (username, u['id'])).fetchone():
            return jsonify(error='Занят'), 400
        db.execute('UPDATE users SET username=? WHERE id=?', (username, u['id']))
    if 'bio' in d:
        bio = (d.get('bio') or '').strip()[:200]
        db.execute('UPDATE users SET bio=? WHERE id=?', (bio, u['id']))
    if d.get('password'):
        old = d.get('old_password') or ''
        h_old, _ = hash_pw(old, u['salt'])
        if not secrets.compare_digest(h_old, u['pw_hash']): return jsonify(error='Неверный старый пароль'), 400
        if len(d['password']) < 6: return jsonify(error='Пароль минимум 6'), 400
        h, s = hash_pw(d['password'])
        db.execute('UPDATE users SET pw_hash=?, salt=? WHERE id=?', (h, s, u['id']))
    db.commit(); return jsonify(ok=True)

@app.delete('/api/me')
@auth
def delete_me():
    d = request.get_json(force=True) or {}
    pw = d.get('password') or ''
    db = get_db(); u = me()
    h, _ = hash_pw(pw, u['salt'])
    if not secrets.compare_digest(h, u['pw_hash']): return jsonify(error='Неверный пароль'), 400
    uid = u['id']
    db.execute('DELETE FROM members WHERE user_id=?', (uid,))
    db.execute('DELETE FROM reactions WHERE user_id=?', (uid,))
    db.execute('DELETE FROM typing WHERE user_id=?', (uid,))
    db.execute('DELETE FROM blocks WHERE user_id=? OR blocked_id=?', (uid, uid))
    db.execute('DELETE FROM hidden_chats WHERE user_id=?', (uid,))
    db.execute('DELETE FROM wallpapers WHERE user_id=?', (uid,))
    db.execute('DELETE FROM folders WHERE user_id=?', (uid,))
    db.execute('DELETE FROM secret_keys WHERE user_id=?', (uid,))
    db.execute('DELETE FROM poll_votes WHERE user_id=?', (uid,))
    packs = db.execute('SELECT id FROM sticker_packs WHERE owner_id=?', (uid,)).fetchall()
    for p in packs: db.execute('DELETE FROM pack_stickers WHERE pack_id=?', (p['id'],))
    db.execute('DELETE FROM sticker_packs WHERE owner_id=?', (uid,))
    db.execute('UPDATE messages SET sender_id=0 WHERE sender_id=?', (uid,))
    for c in db.execute('SELECT id FROM chats WHERE owner_id=?', (uid,)).fetchall():
        db.execute('DELETE FROM messages WHERE chat_id=?', (c['id'],))
        db.execute('DELETE FROM members WHERE chat_id=?', (c['id'],))
        db.execute('DELETE FROM pinned WHERE chat_id=?', (c['id'],))
        db.execute('DELETE FROM chats WHERE id=?', (c['id'],))
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit(); session.clear()
    return jsonify(ok=True)

@app.get('/api/users')
@auth
def search_users():
    q = (request.args.get('q') or '').strip().lstrip('@').lower()
    db = get_db(); u = me()
    blocked = {r[0] for r in db.execute('SELECT blocked_id FROM blocks WHERE user_id=?', (u['id'],)).fetchall()}
    if not q:
        rows = db.execute('SELECT * FROM users WHERE id!=? AND banned=0 ORDER BY id LIMIT 50', (u['id'],)).fetchall()
    else:
        rows = db.execute('SELECT * FROM users WHERE id!=? AND banned=0 AND (username LIKE ? OR lower(name) LIKE ?) LIMIT 50',
                          (u['id'], f'%{q}%', f'%{q}%')).fetchall()
    return jsonify([user_json(r) for r in rows if r['id'] not in blocked])

# ---------- FOLDERS ----------
@app.get('/api/folders')
@auth
def list_folders():
    db = get_db(); u = me()
    rows = db.execute('SELECT * FROM folders WHERE user_id=? ORDER BY position, id', (u['id'],)).fetchall()
    out = []
    for f in rows:
        cids = [r[0] for r in db.execute('SELECT chat_id FROM folder_chats WHERE folder_id=?', (f['id'],)).fetchall()]
        out.append({'id': f['id'], 'name': f['name'], 'position': f['position'], 'chat_ids': cids})
    return jsonify(out)

@app.post('/api/folders')
@auth
def create_folder():
    d = request.get_json(force=True) or {}
    name = (d.get('name') or '').strip()
    if not name or len(name) > 30: return jsonify(error='Некорректное имя'), 400
    cids = d.get('chat_ids') or []
    db = get_db(); u = me()
    fid = db.execute('INSERT INTO folders(user_id,name,position,created) VALUES(?,?,?,?)',
                     (u['id'], name, 0, time.time())).lastrowid
    for cid in cids[:100]:
        try: cid = int(cid)
        except: continue
        db.execute('INSERT OR IGNORE INTO folder_chats VALUES(?,?)', (fid, cid))
    db.commit(); return jsonify(id=fid)

@app.patch('/api/folders/<int:fid>')
@auth
def update_folder(fid):
    d = request.get_json(force=True) or {}
    db = get_db(); u = me()
    f = db.execute('SELECT * FROM folders WHERE id=? AND user_id=?', (fid, u['id'])).fetchone()
    if not f: return jsonify(error='Не найдено'), 404
    if 'name' in d:
        name = (d.get('name') or '').strip()[:30]
        if name: db.execute('UPDATE folders SET name=? WHERE id=?', (name, fid))
    if 'chat_ids' in d:
        db.execute('DELETE FROM folder_chats WHERE folder_id=?', (fid,))
        for cid in (d['chat_ids'] or [])[:100]:
            try: cid = int(cid)
            except: continue
            db.execute('INSERT OR IGNORE INTO folder_chats VALUES(?,?)', (fid, cid))
    db.commit(); return jsonify(ok=True)

@app.delete('/api/folders/<int:fid>')
@auth
def delete_folder(fid):
    db = get_db(); u = me()
    db.execute('DELETE FROM folders WHERE id=? AND user_id=?', (fid, u['id']))
    db.execute('DELETE FROM folder_chats WHERE folder_id=?', (fid,))
    db.commit(); return jsonify(ok=True)

# ---------- CHATS ----------
@app.get('/api/chats')
@auth
def list_chats():
    db = get_db(); u = me(); now = time.time()
    rows = db.execute('''SELECT c.* FROM chats c JOIN members m ON m.chat_id=c.id
                         WHERE m.user_id=? ORDER BY c.id DESC''', (u['id'],)).fetchall()
    blocked_ids = {r[0] for r in db.execute('SELECT blocked_id FROM blocks WHERE user_id=?', (u['id'],)).fetchall()}
    out = []
    for c in rows:
        last = db.execute('''SELECT * FROM messages WHERE chat_id=? AND COALESCE(deleted,0)=0
                             ORDER BY id DESC LIMIT 1''', (c['id'],)).fetchone()
        h = db.execute('SELECT hidden_at FROM hidden_chats WHERE user_id=? AND chat_id=?',
                       (u['id'], c['id'])).fetchone()
        if h and (not last or last['created'] <= h['hidden_at']): continue
        peer = None
        if c['type'] == 'dm':
            peer = db.execute('''SELECT u.* FROM users u JOIN members m ON m.user_id=u.id
                                 WHERE m.chat_id=? AND u.id!=?''', (c['id'], u['id'])).fetchone()
        last_json = None
        if last and last['sender_id'] not in blocked_ids:
            s = db.execute('SELECT name FROM users WHERE id=?', (last['sender_id'],)).fetchone()
            txt = decrypt_text(last['text'])
            last_json = {'id': last['id'], 'sender': s['name'] if s else 'Удалён',
                         'text': txt[:80], 'file': bool(last['file_id']),
                         'is_sticker': bool(last['is_sticker']),
                         'is_voice': bool(last['is_voice']),
                         'is_secret': bool(c['is_secret']),
                         'created': last['created']}
        title, avatar = c['name'], c['avatar']
        peer_status = None
        if c['type'] == 'dm' and peer:
            title, avatar = peer['name'], peer['avatar']
            peer_status = user_status(peer)
        typ = db.execute('''SELECT u.name FROM typing t JOIN users u ON u.id=t.user_id
                            WHERE t.chat_id=? AND t.user_id!=? AND t.ts > ?''',
                         (c['id'], u['id'], now - TYPING_WINDOW)).fetchall()
        out.append({'id': c['id'], 'type': c['type'], 'title': title or 'Чат',
                    'avatar': avatar, 'peer_id': peer['id'] if peer else None,
                    'peer_status': peer_status,
                    'typing': [t['name'] for t in typ],
                    'slow_mode': c['slow_mode'] or 0,
                    'is_secret': bool(c['is_secret']),
                    'last': last_json})
    return jsonify(out)

@app.post('/api/chats')
@auth
def create_chat():
    d = request.get_json(force=True) or {}
    t = d.get('type'); u = me(); db = get_db()
    if t == 'dm':
        try: peer = int(d.get('user_id') or 0)
        except: return jsonify(error='bad user'), 400
        if peer == u['id']: return jsonify(error='Нельзя с собой'), 400
        if not db.execute('SELECT 1 FROM users WHERE id=? AND banned=0', (peer,)).fetchone():
            return jsonify(error='Не найден'), 404
        existing = db.execute('''SELECT c.id FROM chats c
            JOIN members m1 ON m1.chat_id=c.id AND m1.user_id=?
            JOIN members m2 ON m2.chat_id=c.id AND m2.user_id=?
            WHERE c.type='dm' LIMIT 1''', (u['id'], peer)).fetchone()
        if existing:
            db.execute('DELETE FROM hidden_chats WHERE chat_id=?', (existing['id'],))
            db.commit(); return jsonify(id=existing['id'])
        cur = db.execute('INSERT INTO chats(type,owner_id,created) VALUES(?,?,?)', ('dm', u['id'], time.time()))
        cid = cur.lastrowid
        db.execute('INSERT INTO members(chat_id,user_id,can_send,joined) VALUES(?,?,1,?)', (cid, u['id'], time.time()))
        db.execute('INSERT INTO members(chat_id,user_id,can_send,joined) VALUES(?,?,1,?)', (cid, peer, time.time()))
        db.commit(); return jsonify(id=cid)
    if t == 'secret':
        try: peer = int(d.get('user_id') or 0)
        except: return jsonify(error='bad user'), 400
        if peer == u['id']: return jsonify(error='Нельзя с собой'), 400
        existing = db.execute('''SELECT c.id FROM chats c
            JOIN members m1 ON m1.chat_id=c.id AND m1.user_id=?
            JOIN members m2 ON m2.chat_id=c.id AND m2.user_id=?
            WHERE c.type='secret' LIMIT 1''', (u['id'], peer)).fetchone()
        if existing: return jsonify(id=existing['id'])
        cur = db.execute('INSERT INTO chats(type,owner_id,is_secret,created) VALUES(?,?,1,?)',
                         ('secret', u['id'], time.time()))
        cid = cur.lastrowid
        db.execute('INSERT INTO members(chat_id,user_id,can_send,joined) VALUES(?,?,1,?)', (cid, u['id'], time.time()))
        db.execute('INSERT INTO members(chat_id,user_id,can_send,joined) VALUES(?,?,1,?)', (cid, peer, time.time()))
        db.commit(); return jsonify(id=cid)
    if t in ('group', 'channel'):
        name = (d.get('name') or '').strip()
        if not name or len(name) > 60: return jsonify(error='Некорректное имя'), 400
        inv = secrets.token_urlsafe(10)
        cur = db.execute('''INSERT INTO chats(type,name,owner_id,invite_hash,description,created)
                            VALUES(?,?,?,?,?,?)''',
                         (t, name, u['id'], inv, (d.get('description') or '')[:200], time.time()))
        cid = cur.lastrowid
        db.execute('''INSERT INTO members(chat_id,user_id,is_admin,can_send,can_invite,can_pin,can_delete,joined)
                      VALUES(?,?,1,1,1,1,1,?)''', (cid, u['id'], time.time()))
        db.commit(); return jsonify(id=cid, invite=inv)
    return jsonify(error='Неверный тип'), 400

@app.get('/api/chats/<int:cid>')
@auth
def chat_info(cid):
    db = get_db(); u = me()
    mship = my_membership(db, cid)
    if not mship: return jsonify(error='Нет доступа'), 403
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if not c: abort(404)
    base = {'id': c['id'], 'type': c['type'], 'name': c['name'],
            'owner_id': c['owner_id'], 'description': c['description'] or '',
            'slow_mode': c['slow_mode'] or 0, 'invite_hash': c['invite_hash'],
            'comments_chat_id': c['comments_chat_id'],
            'is_secret': bool(c['is_secret']),
            'my_perms': member_json(mship)}
    if c['type'] in ('dm','secret'):
        peer = db.execute('''SELECT u.* FROM users u JOIN members m ON m.user_id=u.id
                             WHERE m.chat_id=? AND u.id!=?''', (cid, u['id'])).fetchone()
        base['peer'] = user_json(peer)
        if c['type'] == 'dm':
            base['blocked_by_me'] = bool(peer and db.execute('SELECT 1 FROM blocks WHERE user_id=? AND blocked_id=?',
                                                              (u['id'], peer['id'])).fetchone())
            base['i_am_blocked'] = bool(peer and db.execute('SELECT 1 FROM blocks WHERE user_id=? AND blocked_id=?',
                                                             (peer['id'], u['id'])).fetchone())
            base['is_dev_local'] = is_dev_local()
        return jsonify(base)
    members = db.execute('''SELECT u.*, m.is_admin, m.can_send, m.can_invite, m.can_pin, m.can_delete, m.user_id
                            FROM users u JOIN members m ON m.user_id=u.id
                            WHERE m.chat_id=?''', (cid,)).fetchall()
    base['members'] = [dict(user_json(r), **member_json(r)) for r in members]
    return jsonify(base)

@app.post('/api/chats/<int:cid>/members')
@auth
def add_member(cid):
    d = request.get_json(force=True) or {}
    uname = (d.get('username') or '').strip().lstrip('@').lower()
    db = get_db(); u = me()
    mship = my_membership(db, cid)
    if not mship: return jsonify(error='Нет доступа'), 403
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if not c or c['type'] in ('dm','secret'): return jsonify(error='Недоступно'), 400
    if not (mship['is_admin'] or mship['can_invite']): return jsonify(error='Нет прав'), 403
    t = db.execute('SELECT * FROM users WHERE username=? AND banned=0', (uname,)).fetchone()
    if not t: return jsonify(error='Не найден'), 404
    if db.execute('SELECT 1 FROM members WHERE chat_id=? AND user_id=?', (cid, t['id'])).fetchone():
        return jsonify(error='Уже участник'), 400
    db.execute('INSERT INTO members(chat_id,user_id,is_admin,can_send,joined) VALUES(?,?,0,1,?)',
               (cid, t['id'], time.time()))
    db.execute('DELETE FROM hidden_chats WHERE user_id=? AND chat_id=?', (t['id'], cid))
    db.commit(); return jsonify(ok=True)

@app.post('/api/join/<invite>')
@auth
def join_invite(invite):
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM chats WHERE invite_hash=?', (invite,)).fetchone()
    if not c: return jsonify(error='Ссылка недействительна'), 404
    if db.execute('SELECT 1 FROM members WHERE chat_id=? AND user_id=?', (c['id'], u['id'])).fetchone():
        return jsonify(id=c['id'])
    db.execute('INSERT INTO members(chat_id,user_id,is_admin,can_send,joined) VALUES(?,?,0,1,?)',
               (c['id'], u['id'], time.time()))
    db.execute('DELETE FROM hidden_chats WHERE user_id=? AND chat_id=?', (u['id'], c['id']))
    db.commit(); return jsonify(id=c['id'])

@app.post('/api/chats/<int:cid>/rotate_invite')
@auth
def rotate_invite(cid):
    db = get_db(); u = me()
    mship = my_membership(db, cid)
    if not mship: return jsonify(error='Нет доступа'), 403
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if c['owner_id'] != u['id'] and not mship['is_admin']: return jsonify(error='Нет прав'), 403
    inv = secrets.token_urlsafe(10)
    db.execute('UPDATE chats SET invite_hash=? WHERE id=?', (inv, cid)); db.commit()
    return jsonify(invite=inv)

@app.patch('/api/chats/<int:cid>/member/<int:uid>')
@auth
def set_member_perm(cid, uid):
    d = request.get_json(force=True) or {}
    db = get_db(); u = me()
    mship = my_membership(db, cid)
    if not mship or not mship['is_admin']: return jsonify(error='Нет прав'), 403
    target = db.execute('SELECT * FROM members WHERE chat_id=? AND user_id=?', (cid, uid)).fetchone()
    if not target: return jsonify(error='Не участник'), 404
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if uid == c['owner_id'] and 'is_admin' in d and not d['is_admin']:
        return jsonify(error='Нельзя снять владельца'), 400
    for k in ('is_admin','can_send','can_invite','can_pin','can_delete'):
        if k in d:
            db.execute(f'UPDATE members SET {k}=? WHERE chat_id=? AND user_id=?',
                       (1 if d[k] else 0, cid, uid))
    db.commit(); return jsonify(ok=True)

@app.post('/api/chats/<int:cid>/leave')
@auth
def leave_chat(cid):
    db = get_db(); u = me()
    db.execute('DELETE FROM members WHERE chat_id=? AND user_id=?', (cid, u['id']))
    db.commit(); return jsonify(ok=True)

@app.post('/api/chats/<int:cid>/hide')
@auth
def hide_chat(cid):
    db = get_db(); u = me()
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    db.execute('INSERT OR REPLACE INTO hidden_chats VALUES(?,?,?)', (u['id'], cid, time.time()))
    db.commit(); return jsonify(ok=True)

@app.patch('/api/chats/<int:cid>')
@auth
def update_chat(cid):
    d = request.get_json(force=True) or {}
    db = get_db(); u = me()
    mship = my_membership(db, cid)
    if not mship or not mship['is_admin']: return jsonify(error='Нет прав'), 403
    if 'name' in d:
        name = (d.get('name') or '').strip()[:60]
        if name: db.execute('UPDATE chats SET name=? WHERE id=?', (name, cid))
    if 'description' in d:
        desc = (d.get('description') or '').strip()[:200]
        db.execute('UPDATE chats SET description=? WHERE id=?', (desc, cid))
    if 'slow_mode' in d:
        try: sm = max(0, min(3600, int(d['slow_mode'])))
        except: sm = 0
        db.execute('UPDATE chats SET slow_mode=? WHERE id=?', (sm, cid))
    db.commit(); return jsonify(ok=True)

@app.delete('/api/chats/<int:cid>')
@auth
def delete_chat(cid):
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if not c: return jsonify(error='Не найден'), 404
    if c['type'] in ('dm','secret'):
        db.execute('INSERT OR REPLACE INTO hidden_chats VALUES(?,?,?)', (u['id'], cid, time.time()))
        db.commit(); return jsonify(hidden=True)
    if c['owner_id'] != u['id']: return jsonify(error='Только владелец'), 403
    db.execute('DELETE FROM messages WHERE chat_id=?', (cid,))
    db.execute('DELETE FROM members WHERE chat_id=?', (cid,))
    db.execute('DELETE FROM pinned WHERE chat_id=?', (cid,))
    db.execute('DELETE FROM typing WHERE chat_id=?', (cid,))
    db.execute('DELETE FROM chats WHERE id=?', (cid,))
    db.commit(); return jsonify(deleted=True)

@app.get('/api/chats/<int:cid>/wallpaper')
@auth
def get_wp(cid):
    db = get_db(); u = me()
    r = db.execute('SELECT value FROM wallpapers WHERE user_id=? AND chat_id=?', (u['id'], cid)).fetchone()
    return jsonify(value=r['value'] if r else 'default')

@app.post('/api/chats/<int:cid>/wallpaper')
@auth
def set_wp(cid):
    d = request.get_json(force=True) or {}
    v = (d.get('value') or 'default')[:60]
    db = get_db(); u = me()
    db.execute('INSERT OR REPLACE INTO wallpapers VALUES(?,?,?)', (u['id'], cid, v)); db.commit()
    return jsonify(ok=True)

# ---------- TYPING ----------
@app.post('/api/chats/<int:cid>/typing')
@auth
def set_typing(cid):
    db = get_db(); u = me()
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    db.execute('INSERT OR REPLACE INTO typing VALUES(?,?,?)', (u['id'], cid, time.time()))
    db.commit(); return jsonify(ok=True)

# ---------- PIN ----------
@app.post('/api/chats/<int:cid>/pin/<int:mid>')
@auth
def pin_msg(cid, mid):
    db = get_db(); u = me()
    mship = my_membership(db, cid)
    if not mship: return jsonify(error='Нет доступа'), 403
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if c['type'] in ('group','channel') and not (mship['is_admin'] or mship['can_pin']):
        return jsonify(error='Нет прав'), 403
    m = db.execute('SELECT * FROM messages WHERE id=? AND chat_id=?', (mid, cid)).fetchone()
    if not m: return jsonify(error='Не найдено'), 404
    db.execute('INSERT OR REPLACE INTO pinned VALUES(?,?,?,?)', (cid, mid, u['id'], time.time()))
    db.commit(); return jsonify(ok=True)

@app.delete('/api/chats/<int:cid>/pin/<int:mid>')
@auth
def unpin_msg(cid, mid):
    db = get_db(); u = me()
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    db.execute('DELETE FROM pinned WHERE chat_id=? AND message_id=?', (cid, mid)); db.commit()
    return jsonify(ok=True)

# ---------- REACTIONS ----------
@app.post('/api/messages/<int:mid>/reactions')
@auth
def toggle_reaction(mid):
    d = request.get_json(force=True) or {}
    emoji = (d.get('emoji') or '').strip()
    if emoji not in REACTIONS: return jsonify(error='Недопустимо'), 400
    db = get_db(); u = me()
    m = db.execute('SELECT * FROM messages WHERE id=?', (mid,)).fetchone()
    if not m: return jsonify(error='Не найдено'), 404
    if not my_membership(db, m['chat_id']): return jsonify(error='Нет доступа'), 403
    ex = db.execute('SELECT 1 FROM reactions WHERE message_id=? AND user_id=? AND emoji=?',
                    (mid, u['id'], emoji)).fetchone()
    if ex:
        db.execute('DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?',
                   (mid, u['id'], emoji))
    else:
        db.execute('INSERT INTO reactions VALUES(?,?,?)', (mid, u['id'], emoji))
    db.commit()
    rows = db.execute('SELECT user_id, emoji FROM reactions WHERE message_id=?', (mid,)).fetchall()
    grouped = defaultdict(list)
    for r in rows: grouped[r['emoji']].append(r['user_id'])
    return jsonify([{'emoji': e, 'count': len(us), 'user_ids': us} for e, us in grouped.items()])

# ---------- POLLS ----------
@app.post('/api/chats/<int:cid>/polls')
@auth
def create_poll(cid):
    d = request.get_json(force=True) or {}
    question = (d.get('question') or '').strip()[:200]
    options = [str(o).strip()[:80] for o in (d.get('options') or []) if str(o).strip()]
    multiple = 1 if d.get('multiple') else 0
    anonymous = 1 if d.get('anonymous') else 0
    closes_at = 0
    if d.get('closes_in'):
        try: closes_at = time.time() + max(60, min(86400*7, int(d['closes_in'])))
        except: pass
    if not question or len(options) < 2: return jsonify(error='Введите вопрос и 2+ варианта'), 400
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if not c: return jsonify(error='Не найден'), 404
    mship = my_membership(db, cid)
    if not can_post(db, c, mship): return jsonify(error='Нет прав'), 403
    cur = db.execute('INSERT INTO messages(chat_id,sender_id,created) VALUES(?,?,?)',
                     (cid, u['id'], time.time()))
    mid = cur.lastrowid
    pid = db.execute('''INSERT INTO polls(message_id,question,options,multiple,anonymous,closes_at,created)
                        VALUES(?,?,?,?,?,?,?)''',
                     (mid, question, json.dumps(options, ensure_ascii=False),
                      multiple, anonymous, closes_at, time.time())).lastrowid
    db.execute('UPDATE messages SET poll_id=? WHERE id=?', (pid, mid))
    db.execute('DELETE FROM hidden_chats WHERE chat_id=?', (cid,))
    db.commit(); return jsonify(id=mid)

@app.post('/api/polls/<int:pid>/vote')
@auth
def vote_poll(pid):
    d = request.get_json(force=True) or {}
    try: opt = int(d.get('option'))
    except: return jsonify(error='bad'), 400
    db = get_db(); u = me()
    p = db.execute('SELECT * FROM polls WHERE id=?', (pid,)).fetchone()
    if not p: return jsonify(error='Не найдено'), 404
    if p['closes_at'] and time.time() > p['closes_at']: return jsonify(error='Опрос закрыт'), 400
    opts = json.loads(p['options'])
    if opt < 0 or opt >= len(opts): return jsonify(error='bad'), 400
    m = db.execute('SELECT chat_id FROM messages WHERE id=?', (p['message_id'],)).fetchone()
    if not m or not my_membership(db, m['chat_id']): return jsonify(error='Нет доступа'), 403
    if not p['multiple']:
        db.execute('DELETE FROM poll_votes WHERE poll_id=? AND user_id=?', (pid, u['id']))
    ex = db.execute('SELECT 1 FROM poll_votes WHERE poll_id=? AND user_id=? AND option_idx=?',
                    (pid, u['id'], opt)).fetchone()
    if ex:
        db.execute('DELETE FROM poll_votes WHERE poll_id=? AND user_id=? AND option_idx=?',
                   (pid, u['id'], opt))
    else:
        db.execute('INSERT INTO poll_votes VALUES(?,?,?)', (pid, u['id'], opt))
    db.commit()
    return jsonify(build_poll(db, pid, u['id']))

# ---------- EDIT / DELETE ----------
@app.patch('/api/messages/<int:mid>')
@auth
def edit_message(mid):
    d = request.get_json(force=True) or {}
    text = (d.get('text') or '').strip()
    if not text or len(text) > 4000: return jsonify(error='Некорректный текст'), 400
    db = get_db(); u = me()
    m = db.execute('SELECT * FROM messages WHERE id=?', (mid,)).fetchone()
    if not m or m['deleted']: return jsonify(error='Недоступно'), 400
    if m['sender_id'] != u['id']: return jsonify(error='Только автор'), 403
    if m['file_id'] or m['poll_id']: return jsonify(error='Нельзя редактировать'), 400
    enc = FERNET.encrypt(text.encode('utf-8'))
    db.execute('UPDATE messages SET text=?, edited=1 WHERE id=?', (enc, mid)); db.commit()
    return jsonify(ok=True)

@app.delete('/api/messages/<int:mid>')
@auth
def delete_message(mid):
    db = get_db(); u = me()
    m = db.execute('SELECT * FROM messages WHERE id=?', (mid,)).fetchone()
    if not m: return jsonify(error='Не найдено'), 404
    mship = my_membership(db, m['chat_id'])
    if not mship: return jsonify(error='Нет доступа'), 403
    c = db.execute('SELECT * FROM chats WHERE id=?', (m['chat_id'],)).fetchone()
    is_owner = bool(c and c['owner_id'] == u['id'])
    if m['sender_id'] != u['id'] and not is_owner and not mship['can_delete'] and not mship['is_admin']:
        return jsonify(error='Нет прав'), 403
    db.execute('UPDATE messages SET deleted=1, text=NULL, file_id=NULL WHERE id=?', (mid,))
    db.execute('DELETE FROM reactions WHERE message_id=?', (mid,))
    db.execute('DELETE FROM pinned WHERE message_id=?', (mid,))
    db.commit(); return jsonify(ok=True)

# ---------- MESSAGES ----------
@app.get('/api/chats/<int:cid>/messages')
@auth
def get_messages(cid):
    u = me(); db = get_db()
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    try: after = int(request.args.get('after') or 0)
    except: after = 0
    blocked_ids = {r[0] for r in db.execute('SELECT blocked_id FROM blocks WHERE user_id=?', (u['id'],)).fetchall()}
    rows = db.execute('SELECT * FROM messages WHERE chat_id=? AND id>? ORDER BY id ASC LIMIT 300',
                      (cid, after)).fetchall()
    out = []
    for r in rows:
        m = build_message(db, r, u['id'], blocked_ids)
        if m: out.append(m)
    attach_reactions(db, out)

    deleted_ids = []
    if after > 0:
        min_id = max(0, after - 500)
        drs = db.execute('''SELECT id FROM messages WHERE chat_id=? AND deleted=1 AND id>? AND id<=?''',
                         (cid, min_id, after)).fetchall()
        deleted_ids = [dr['id'] for dr in drs]

    now = time.time()
    db.execute('DELETE FROM typing WHERE ts < ?', (now - 30,)); db.commit()
    typ = db.execute('''SELECT u.name FROM typing t JOIN users u ON u.id=t.user_id
                        WHERE t.chat_id=? AND t.user_id!=? AND t.ts > ?''',
                     (cid, u['id'], now - TYPING_WINDOW)).fetchall()
    peer_status = None
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if c and c['type'] == 'dm':
        peer = db.execute('''SELECT u.* FROM users u JOIN members m ON m.user_id=u.id
                             WHERE m.chat_id=? AND u.id!=?''', (cid, u['id'])).fetchone()
        if peer: peer_status = user_status(peer)
    pin_rows = db.execute('''SELECT m.* FROM pinned p JOIN messages m ON m.id=p.message_id
                             WHERE p.chat_id=? AND COALESCE(m.deleted,0)=0
                             ORDER BY p.pinned_at DESC''', (cid,)).fetchall()
    pinned = []
    for pr in pin_rows:
        pm = build_message(db, pr, u['id'], blocked_ids)
        if pm: pinned.append(pm)
    attach_reactions(db, pinned)
    return jsonify({'messages': out, 'deleted_ids': deleted_ids,
                    'typing': [t['name'] for t in typ], 'peer_status': peer_status,
                    'pinned': pinned})

@app.get('/api/chats/<int:cid>/search')
@auth
def search_msgs(cid):
    u = me(); db = get_db()
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    q = (request.args.get('q') or '').strip().lower()
    if len(q) < 2: return jsonify([])
    blocked_ids = {r[0] for r in db.execute('SELECT blocked_id FROM blocks WHERE user_id=?', (u['id'],)).fetchall()}
    rows = db.execute('''SELECT * FROM messages WHERE chat_id=? AND COALESCE(deleted,0)=0
                         ORDER BY id DESC LIMIT 1000''', (cid,)).fetchall()
    out = []
    for r in rows:
        if r['enc']: continue
        txt = decrypt_text(r['text'])
        if q in txt.lower():
            m = build_message(db, r, u['id'], blocked_ids)
            if m: out.append(m)
            if len(out) >= 50: break
    return jsonify(out)

@app.post('/api/chats/<int:cid>/messages')
@auth
def send_message(cid):
    u = me(); db = get_db()
    mship = my_membership(db, cid)
    if not mship: return jsonify(error='Нет доступа'), 403
    c = db.execute('SELECT * FROM chats WHERE id=?', (cid,)).fetchone()
    if not can_post(db, c, mship): return jsonify(error='Нет прав писать'), 403
    sm = c['slow_mode'] or 0
    if sm and not mship['is_admin']:
        last = db.execute('''SELECT created FROM messages WHERE chat_id=? AND sender_id=?
                             ORDER BY id DESC LIMIT 1''', (cid, u['id'])).fetchone()
        if last and (time.time() - last['created']) < sm:
            return jsonify(error='Медленный режим: подождите %d сек' % int(sm - (time.time() - last['created']))), 429
    if c['type'] == 'dm':
        peer = db.execute('''SELECT u.* FROM users u JOIN members m ON m.user_id=u.id
                             WHERE m.chat_id=? AND u.id!=?''', (cid, u['id'])).fetchone()
        if peer:
            if peer['banned']: return jsonify(error='Заблокирован'), 403
            if db.execute('SELECT 1 FROM blocks WHERE user_id=? AND blocked_id=?',
                          (peer['id'], u['id'])).fetchone():
                return jsonify(error='Вы заблокированы'), 403
    d = request.get_json(force=True) or {}
    text = (d.get('text') or '').strip()
    file_id = d.get('file_id')
    sticker_id = d.get('sticker_id')
    reply_to = d.get('reply_to')
    is_voice = 1 if d.get('is_voice') else 0
    duration = float(d.get('duration') or 0)
    is_sticker = 0
    if sticker_id:
        st = db.execute('SELECT * FROM pack_stickers WHERE id=?', (sticker_id,)).fetchone()
        if not st: return jsonify(error='Стикер не найден'), 404
        pk = db.execute('SELECT * FROM sticker_packs WHERE id=?', (st['pack_id'],)).fetchone()
        if not pk or (pk['owner_id'] != u['id'] and not pk['is_official']):
            return jsonify(error='Нет доступа'), 403
        file_id = st['file_id']; is_sticker = 1
    if file_id:
        try: file_id = int(file_id)
        except: file_id = None
        if file_id and not db.execute('SELECT 1 FROM files WHERE id=?', (file_id,)).fetchone():
            return jsonify(error='Файл не найден'), 404
    if not text and not file_id: return jsonify(error='Пусто'), 400
    if len(text) > 4000: return jsonify(error='Слишком длинное'), 400
    if reply_to:
        try: reply_to = int(reply_to)
        except: reply_to = None
        if reply_to and not db.execute('SELECT 1 FROM messages WHERE id=? AND chat_id=?',
                                       (reply_to, cid)).fetchone():
            reply_to = None
    blob = FERNET.encrypt(text.encode('utf-8')) if text else None
    cur = db.execute('''INSERT INTO messages(chat_id,sender_id,text,file_id,is_sticker,is_voice,
                        duration,deleted,reply_to,edited,enc,created)
                        VALUES(?,?,?,?,?,?,?,0,?,0,0,?)''',
                     (cid, u['id'], blob, file_id, is_sticker, is_voice, duration, reply_to, time.time()))
    db.execute('DELETE FROM hidden_chats WHERE chat_id=?', (cid,))
    db.execute('DELETE FROM typing WHERE chat_id=? AND user_id=?', (cid, u['id']))
    db.commit()
    return jsonify(id=cur.lastrowid)

# ---------- FILES ----------
@app.post('/api/upload_multi')
@auth
def upload_multi():
    files = request.files.getlist('files') or request.files.getlist('file')
    if not files: return jsonify(error='Нет файлов'), 400
    db = get_db(); out = []
    for f in files[:20]:
        name = f.filename or 'file'
        data = f.read()
        if not data: continue
        mime = f.mimetype or mimetypes.guess_type(name)[0] or 'application/octet-stream'
        fn = secrets.token_hex(16) + '.bin'
        (FILES / fn).write_bytes(FERNET.encrypt(data))
        fid = db.execute('INSERT INTO files(name,mime,size,path) VALUES(?,?,?,?)',
                         (name, mime, len(data), fn)).lastrowid
        out.append({'id': fid, 'name': name, 'mime': mime, 'size': len(data)})
    db.commit(); return jsonify(out)

@app.post('/api/upload')
@auth
def upload():
    if 'file' not in request.files: return jsonify(error='Нет файла'), 400
    f = request.files['file']; name = f.filename or 'file'; data = f.read()
    if not data: return jsonify(error='Пустой файл'), 400
    mime = f.mimetype or mimetypes.guess_type(name)[0] or 'application/octet-stream'
    fn = secrets.token_hex(16) + '.bin'
    (FILES / fn).write_bytes(FERNET.encrypt(data))
    db = get_db()
    cur = db.execute('INSERT INTO files(name,mime,size,path) VALUES(?,?,?,?)',
                     (name, mime, len(data), fn)); db.commit()
    return jsonify(id=cur.lastrowid, name=name, mime=mime, size=len(data))

@app.get('/api/files/<int:fid>')
@auth
def download(fid):
    db = get_db()
    fr = db.execute('SELECT * FROM files WHERE id=?', (fid,)).fetchone()
    if not fr: abort(404)
    p = FILES / fr['path']
    if not p.exists(): abort(404)
    data = FERNET.decrypt(p.read_bytes())
    mime = fr['mime'] or 'application/octet-stream'
    force_dl = request.args.get('download') == '1'
    inline = (not force_dl) and (mime.startswith(('image/', 'video/', 'audio/')) or mime == 'application/pdf')
    return send_file(BytesIO(data), mimetype=mime,
                     as_attachment=not inline, download_name=fr['name'] or 'file',
                     conditional=True)

# ---------- AVATARS ----------
@app.post('/api/avatar')
@auth
def upload_avatar():
    if 'file' not in request.files: return jsonify(error='Нет файла'), 400
    f = request.files['file']; data = f.read()
    if len(data) > 6*1024*1024: return jsonify(error='Максимум 6 МБ'), 400
    if not data: return jsonify(error='Пустой'), 400
    fn = secrets.token_hex(16) + '.bin'
    (AVATARS / fn).write_bytes(FERNET.encrypt(data))
    db = get_db(); u = me()
    db.execute('UPDATE users SET avatar=? WHERE id=?', (fn, u['id'])); db.commit()
    return jsonify(avatar=fn)

@app.get('/api/avatars/<name>')
def get_avatar(name):
    if '/' in name or '..' in name: abort(404)
    p = AVATARS / name
    if not p.exists(): abort(404)
    data = FERNET.decrypt(p.read_bytes())
    mime = 'image/jpeg'
    if data[:8] == b'\x89PNG\r\n\x1a\n': mime = 'image/png'
    elif data[:6] in (b'GIF87a', b'GIF89a'): mime = 'image/gif'
    elif data[:4] == b'RIFF' and data[8:12] == b'WEBP': mime = 'image/webp'
    elif data[:2] == b'BM': mime = 'image/bmp'
    return send_file(BytesIO(data), mimetype=mime)

# ---------- BLOCKS ----------
@app.post('/api/blocks/<int:uid>')
@auth
def block_user(uid):
    db = get_db(); u = me()
    if uid == u['id']: return jsonify(error='Нельзя себя'), 400
    db.execute('INSERT OR IGNORE INTO blocks VALUES(?,?,?)', (u['id'], uid, time.time()))
    db.commit(); return jsonify(ok=True)

@app.delete('/api/blocks/<int:uid>')
@auth
def unblock_user(uid):
    db = get_db(); u = me()
    db.execute('DELETE FROM blocks WHERE user_id=? AND blocked_id=?', (u['id'], uid))
    db.commit(); return jsonify(ok=True)

# ---------- CALLS (audio only) ----------
@app.post('/api/calls/start')
@auth
def call_start():
    d = request.get_json(force=True) or {}
    u = me(); db = get_db()
    try:
        callee = int(d.get('callee_id') or 0)
        cid = int(d.get('chat_id') or 0)
    except: return jsonify(error='bad'), 400
    if callee == u['id']: return jsonify(error='С собой нельзя'), 400
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    now = time.time()
    db.execute("UPDATE calls SET state='ended' WHERE state IN ('ringing','active') AND (caller_id=? OR callee_id=?)",
               (u['id'], u['id']))
    cur = db.execute('''INSERT INTO calls(chat_id,caller_id,callee_id,kind,state,created,updated)
                        VALUES(?,?,?,?, 'ringing', ?, ?)''',
                     (cid, u['id'], callee, 'audio', now, now))
    db.commit()
    return jsonify(id=cur.lastrowid)

@app.post('/api/calls/<int:cid>/signal')
@auth
def call_signal(cid):
    d = request.get_json(force=True) or {}
    u = me(); db = get_db()
    c = db.execute('SELECT * FROM calls WHERE id=?', (cid,)).fetchone()
    if not c: return jsonify(error='Нет звонка'), 404
    if u['id'] not in (c['caller_id'], c['callee_id']): return jsonify(error='Нет доступа'), 403
    role = 'caller' if u['id'] == c['caller_id'] else 'callee'
    if 'offer' in d:
        db.execute('UPDATE calls SET offer=?, state="ringing", updated=? WHERE id=?',
                   (json.dumps(d['offer']), time.time(), cid))
    if 'answer' in d:
        db.execute('UPDATE calls SET answer=?, state="active", updated=? WHERE id=?',
                   (json.dumps(d['answer']), time.time(), cid))
    if 'ice' in d:
        col = 'caller_ice' if role == 'caller' else 'callee_ice'
        row = db.execute(f'SELECT {col} FROM calls WHERE id=?', (cid,)).fetchone()
        cur = json.loads(row[0]) if row and row[0] else []
        cur.append(d['ice'])
        db.execute(f'UPDATE calls SET {col}=?, updated=? WHERE id=?',
                   (json.dumps(cur), time.time(), cid))
    if d.get('state'):
        db.execute('UPDATE calls SET state=?, updated=? WHERE id=?', (d['state'], time.time(), cid))
    db.commit(); return jsonify(ok=True)

@app.get('/api/calls/<int:cid>')
@auth
def call_status(cid):
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM calls WHERE id=?', (cid,)).fetchone()
    if not c: return jsonify(error='Нет'), 404
    if u['id'] not in (c['caller_id'], c['callee_id']): return jsonify(error='Нет'), 403
    role = 'caller' if u['id'] == c['caller_id'] else 'callee'
    other_ice_col = 'callee_ice' if role == 'caller' else 'caller_ice'
    other_ice = json.loads(c[other_ice_col]) if c[other_ice_col] else []
    return jsonify({'id': c['id'], 'state': c['state'], 'kind': c['kind'],
                    'role': role,
                    'offer': json.loads(c['offer']) if c['offer'] else None,
                    'answer': json.loads(c['answer']) if c['answer'] else None,
                    'ice': other_ice})

@app.get('/api/calls/incoming')
@auth
def call_incoming():
    db = get_db(); u = me()
    cutoff = time.time() - 60
    c = db.execute('''SELECT * FROM calls WHERE callee_id=? AND state='ringing' AND updated>?
                      ORDER BY id DESC LIMIT 1''', (u['id'], cutoff)).fetchone()
    if not c: return jsonify(None)
    caller = db.execute('SELECT * FROM users WHERE id=?', (c['caller_id'],)).fetchone()
    return jsonify({'id': c['id'], 'chat_id': c['chat_id'], 'kind': c['kind'],
                    'caller': user_json(caller)})

@app.delete('/api/calls/<int:cid>')
@auth
def call_end(cid):
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM calls WHERE id=?', (cid,)).fetchone()
    if not c: return jsonify(ok=True)
    if u['id'] in (c['caller_id'], c['callee_id']):
        db.execute('UPDATE calls SET state="ended", updated=? WHERE id=?', (time.time(), cid))
        db.commit()
    return jsonify(ok=True)

# ---------- SECRET KEYS ----------
@app.get('/api/chats/<int:cid>/secret_key')
@auth
def get_secret_key(cid):
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM chats WHERE id=? AND type=?', (cid, 'secret')).fetchone()
    if not c: return jsonify(error='Не секретный'), 400
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    r = db.execute('SELECT wrapped FROM secret_keys WHERE chat_id=? AND user_id=?',
                   (cid, u['id'])).fetchone()
    return jsonify(wrapped=r['wrapped'] if r else None)

@app.post('/api/chats/<int:cid>/secret_key')
@auth
def set_secret_key(cid):
    d = request.get_json(force=True) or {}
    wrapped = d.get('wrapped') or ''
    db = get_db(); u = me()
    c = db.execute('SELECT * FROM chats WHERE id=? AND type=?', (cid, 'secret')).fetchone()
    if not c: return jsonify(error='Не секретный'), 400
    if not my_membership(db, cid): return jsonify(error='Нет доступа'), 403
    db.execute('INSERT OR REPLACE INTO secret_keys VALUES(?,?,?)', (cid, u['id'], wrapped))
    db.commit(); return jsonify(ok=True)

# ---------- DEV ----------
@app.post('/api/dev/users/<int:uid>/ban')
@auth
def dev_ban(uid):
    if not is_dev_local(): return jsonify(error='Только локально'), 403
    d = request.get_json(force=True) or {}
    val = 1 if d.get('value', True) else 0
    db = get_db()
    db.execute('UPDATE users SET banned=? WHERE id=?', (val, uid)); db.commit()
    return jsonify(ok=True)

@app.delete('/api/dev/users/<int:uid>')
@auth
def dev_delete_user(uid):
    if not is_dev_local(): return jsonify(error='Только локально'), 403
    db = get_db(); u = me()
    if uid == u['id']: return jsonify(error='Себя нельзя'), 400
    db.execute('UPDATE messages SET sender_id=0 WHERE sender_id=?', (uid,))
    db.execute('DELETE FROM members WHERE user_id=?', (uid,))
    db.execute('DELETE FROM blocks WHERE user_id=? OR blocked_id=?', (uid, uid))
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit(); return jsonify(ok=True)

# ---------- STICKER PACKS ----------
@app.get('/api/packs')
@auth
def list_packs():
    u = me(); db = get_db()
    rows = db.execute('''SELECT p.*, u.name AS owner_name, u.is_dev AS owner_is_dev
                         FROM sticker_packs p JOIN users u ON u.id=p.owner_id
                         WHERE p.owner_id=? OR p.is_official=1
                         ORDER BY (p.owner_id=?) DESC, p.id DESC''',
                      (u['id'], u['id'])).fetchall()
    out = []
    for p in rows:
        cnt = db.execute('SELECT COUNT(*) FROM pack_stickers WHERE pack_id=?', (p['id'],)).fetchone()[0]
        first = db.execute('SELECT file_id FROM pack_stickers WHERE pack_id=? ORDER BY id LIMIT 1',
                           (p['id'],)).fetchone()
        out.append({'id': p['id'], 'name': p['name'], 'is_official': bool(p['is_official']),
                    'owner_id': p['owner_id'], 'count': cnt,
                    'cover_file_id': first['file_id'] if first else None,
                    'mine': p['owner_id'] == u['id']})
    return jsonify(out)

@app.post('/api/packs')
@auth
def create_pack():
    d = request.get_json(force=True) or {}
    name = (d.get('name') or '').strip()
    if not name or len(name) > 40: return jsonify(error='Некорректное имя'), 400
    is_off = 1 if d.get('is_official') else 0
    if is_off and not is_dev_local(): return jsonify(error='Только разработчик'), 403
    u = me(); db = get_db()
    pid = db.execute('INSERT INTO sticker_packs(owner_id,name,is_official,created) VALUES(?,?,?,?)',
                     (u['id'], name, is_off, time.time())).lastrowid
    db.commit(); return jsonify(id=pid)

@app.get('/api/packs/<int:pid>')
@auth
def get_pack(pid):
    u = me(); db = get_db()
    p = db.execute('SELECT * FROM sticker_packs WHERE id=?', (pid,)).fetchone()
    if not p: return jsonify(error='Не найден'), 404
    if p['owner_id'] != u['id'] and not p['is_official']: return jsonify(error='Нет'), 403
    stickers = db.execute('''SELECT ps.id, ps.file_id, f.name, f.mime, f.size
                             FROM pack_stickers ps JOIN files f ON f.id=ps.file_id
                             WHERE ps.pack_id=? ORDER BY ps.id''', (pid,)).fetchall()
    return jsonify({'id': p['id'], 'name': p['name'], 'is_official': bool(p['is_official']),
                    'mine': p['owner_id'] == u['id'],
                    'stickers': [{'id': s['id'], 'file': {'id': s['file_id'], 'name': s['name'],
                                                           'mime': s['mime'], 'size': s['size']}} for s in stickers]})

@app.post('/api/packs/<int:pid>/stickers')
@auth
def add_pack_sticker(pid):
    u = me(); db = get_db()
    p = db.execute('SELECT * FROM sticker_packs WHERE id=?', (pid,)).fetchone()
    if not p or p['owner_id'] != u['id']: return jsonify(error='Нет прав'), 403
    if 'file' not in request.files: return jsonify(error='Нет файла'), 400
    f = request.files['file']; data = f.read()
    if not data or len(data) > 2*1024*1024: return jsonify(error='Не подходит'), 400
    mime = f.mimetype or 'image/png'
    if not mime.startswith('image/'): return jsonify(error='Только картинки'), 400
    fn = secrets.token_hex(16) + '.bin'
    (FILES / fn).write_bytes(FERNET.encrypt(data))
    fid = db.execute('INSERT INTO files(name,mime,size,path) VALUES(?,?,?,?)',
                     (f.filename or 'sticker', mime, len(data), fn)).lastrowid
    sid = db.execute('INSERT INTO pack_stickers(pack_id,file_id,created) VALUES(?,?,?)',
                     (pid, fid, time.time())).lastrowid
    db.commit(); return jsonify(id=sid)

@app.delete('/api/packs/<int:pid>/stickers/<int:sid>')
@auth
def del_pack_sticker(pid, sid):
    u = me(); db = get_db()
    p = db.execute('SELECT * FROM sticker_packs WHERE id=?', (pid,)).fetchone()
    if not p or p['owner_id'] != u['id']: return jsonify(error='Нет прав'), 403
    db.execute('DELETE FROM pack_stickers WHERE id=? AND pack_id=?', (sid, pid)); db.commit()
    return jsonify(ok=True)

@app.delete('/api/packs/<int:pid>')
@auth
def del_pack(pid):
    u = me(); db = get_db()
    p = db.execute('SELECT * FROM sticker_packs WHERE id=?', (pid,)).fetchone()
    if not p or p['owner_id'] != u['id']: return jsonify(error='Нет прав'), 403
    db.execute('DELETE FROM pack_stickers WHERE pack_id=?', (pid,))
    db.execute('DELETE FROM sticker_packs WHERE id=?', (pid,)); db.commit()
    return jsonify(ok=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f'Голубь v{APP_VERSION} запущен: http://0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, threaded=True, debug=False)
