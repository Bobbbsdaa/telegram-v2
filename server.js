'use strict';
/* ZadrottzGram server — express + socket.io, хранение в JSON-файле.
   Приватность: сообщения доставляются только в "комнату" пользователя (его userId),
   в которую сокет попадает ТОЛЬКО после проверки токена на сервере. */
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');
const { Server } = require('socket.io');
const scrypt = promisify(crypto.scrypt);

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UP_DIR = path.join(DATA_DIR, 'uploads');
const AV_DIR = path.join(DATA_DIR, 'avatars');
for (const d of [DATA_DIR, UP_DIR, AV_DIR]) fs.mkdirSync(d, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');

const START_STARS = 1000;
const DAILY_STARS = 25;
const MAX_FILE = 8 * 1024 * 1024;
const USER_RE = /^[a-z][a-z0-9_]{3,19}$/;
const USER_MSG = 'Юзернейм: 4–20 символов, латиница, цифры и _, начинается с буквы';

/* ---------- каталог NFT-подарков ---------- */
const GIFTS = [
  { id: 'frog',    name: 'Лягушонок',  emoji: '🐸', price: 25,   supply: 0 },
  { id: 'bear',    name: 'Мишка',      emoji: '🧸', price: 50,   supply: 0 },
  { id: 'rose',    name: 'Роза',       emoji: '🌹', price: 75,   supply: 0 },
  { id: 'cake',    name: 'Тортик',     emoji: '🎂', price: 100,  supply: 0 },
  { id: 'rocket',  name: 'Ракета',     emoji: '🚀', price: 150,  supply: 5000 },
  { id: 'diamond', name: 'Бриллиант',  emoji: '💎', price: 300,  supply: 1000 },
  { id: 'dragon',  name: 'Дракон',     emoji: '🐉', price: 500,  supply: 500 },
  { id: 'crown',   name: 'Корона',     emoji: '👑', price: 1000, supply: 100 },
];
const RARITY = [['common', 70], ['rare', 22], ['epic', 7], ['legendary', 1]];
const rollRarity = () => { let r = Math.random() * 100; for (const [n, w] of RARITY) if ((r -= w) < 0) return n; return 'common'; };

/* ---------- база ---------- */
let db = { users: {}, sessions: {}, chats: {}, items: {}, minted: {}, seq: 0 };
try {
  Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
} catch (e) {
  if (e.code !== 'ENOENT') {
    console.error('Не удалось прочитать db.json, делаю копию и начинаю с чистой базы:', e.message);
    try { fs.renameSync(DB_FILE, DB_FILE + '.broken-' + Date.now()); } catch {}
  }
}
let saveTimer = null;
function writeNow() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; try { writeNow(); } catch (e) { console.error('save', e.message); } }, 500);
}
function flush() { try { writeNow(); } catch (e) { console.error('flush', e.message); } }
process.on('SIGTERM', () => { flush(); process.exit(0); });
process.on('SIGINT', () => { flush(); process.exit(0); });

const byName = new Map();          // username -> userId
const peers = new Map();           // userId -> Set(peerId)
const online = new Map();          // userId -> Set(socketId)
const link = (a, b) => {
  for (const [x, y] of [[a, b], [b, a]]) { if (!peers.has(x)) peers.set(x, new Set()); peers.get(x).add(y); }
};
for (const u of Object.values(db.users)) byName.set(u.username, u.id);
for (const k of Object.keys(db.chats)) { const [a, b] = k.split(':'); link(a, b); }

/* ---------- утилиты ---------- */
const now = () => Date.now();
const chatKey = (a, b) => (a < b ? a + ':' + b : b + ':' + a);
const normUser = s => String(s || '').trim().toLowerCase().replace(/^@/, '');
const hashTok = t => crypto.createHash('sha256').update(t).digest('hex');
const isOn = id => (online.get(id)?.size || 0) > 0;
const hasUser = id => typeof id === 'string' && /^u[a-f0-9]{12}$/.test(id) && Object.hasOwn(db.users, id);
const pub = u => ({ id: u.id, username: u.username, name: u.name, bio: u.bio || '', av: u.av || 0, accent: u.accent || 0, online: isOn(u.id), last: u.last || 0, created: u.created });
const selfView = u => ({ ...pub(u), stars: u.stars, lastDaily: u.lastDaily || 0 });
const catalog = () => GIFTS.map(g => ({ ...g, minted: db.minted[g.id] || 0 }));
const fail = m => { const e = new Error(m); e.userMessage = m; throw e; };

function newSession(uid) {
  const t = crypto.randomBytes(32).toString('hex');
  db.sessions[hashTok(t)] = { uid, ts: now() };
  save();
  return t;
}
function userByToken(t) {
  if (typeof t !== 'string' || t.length !== 64) return null;
  const s = Object.hasOwn(db.sessions, hashTok(t)) ? db.sessions[hashTok(t)] : null;
  return s && hasUser(s.uid) ? db.users[s.uid] : null;
}
async function hashPass(pass, salt = crypto.randomBytes(16)) {
  const hash = await scrypt(pass, salt, 32);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}
async function checkPass(pass, rec) {
  const h = await scrypt(pass, Buffer.from(rec.salt, 'hex'), 32);
  return crypto.timingSafeEqual(h, Buffer.from(rec.hash, 'hex'));
}
const sniffImg = (b, ext) =>
  ext === 'png' ? b.subarray(0, 4).toString('hex') === '89504e47' :
  ext === 'jpg' ? b[0] === 0xff && b[1] === 0xd8 :
  ext === 'gif' ? b.subarray(0, 3).toString() === 'GIF' :
  ext === 'webp' ? b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP' : false;

/* ---------- HTTP ---------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-ancestors 'none'"
  });
  next();
});
app.use(express.json({ limit: '20kb' }));

const tries = new Map();
const tooMany = ip => {
  const t = now(); const r = tries.get(ip) || { n: 0, t };
  if (t - r.t > 600000) { r.n = 0; r.t = t; }
  r.n++; tries.set(ip, r);
  return r.n > 30;
};

app.post('/api/register', async (req, res) => {
  try {
    if (tooMany(req.ip)) return res.status(429).json({ error: 'Слишком много попыток, подождите несколько минут' });
    const { username, password, name } = req.body || {};
    const un = normUser(username);
    if (!USER_RE.test(un)) return res.status(400).json({ error: USER_MSG });
    if (byName.has(un)) return res.status(409).json({ error: 'Юзернейм занят' });
    if (typeof password !== 'string' || password.length < 6 || password.length > 100) return res.status(400).json({ error: 'Пароль: минимум 6 символов' });
    const nm = String(name || '').trim().slice(0, 40) || un;
    const id = 'u' + crypto.randomBytes(6).toString('hex');
    const u = { id, username: un, name: nm, bio: '', av: 0, accent: 0, pass: await hashPass(password), stars: START_STARS, lastDaily: 0, created: now(), last: 0 };
    db.users[id] = u; byName.set(un, id);
    const token = newSession(id);
    save();
    res.json({ token });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    if (tooMany(req.ip)) return res.status(429).json({ error: 'Слишком много попыток, подождите несколько минут' });
    const { username, password } = req.body || {};
    const id = byName.get(normUser(username));
    const u = id && db.users[id];
    if (!u || typeof password !== 'string' || !(await checkPass(password, u.pass))) return res.status(401).json({ error: 'Неверный юзернейм или пароль' });
    res.json({ token: newSession(id) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/logout', (req, res) => {
  const t = String(req.get('authorization') || '').replace(/^Bearer /, '');
  if (userByToken(t)) { delete db.sessions[hashTok(t)]; save(); }
  res.json({ ok: true });
});

// Аватарки публичные
app.get('/avatar/:id', (req, res) => {
  const id = req.params.id;
  if (!hasUser(id) || !db.users[id].av) return res.sendStatus(404);
  res.sendFile(path.join(AV_DIR, id + '.' + db.users[id].avx), { maxAge: '1d' });
});

// Вложения: неугадываемые имена. Всё, кроме картинок/аудио, отдаётся как скачиваемый файл.
const MIME = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', webm: 'audio/webm', ogg: 'audio/ogg', m4a: 'audio/mp4', mp3: 'audio/mpeg', aac: 'audio/aac' };
app.get('/f/:file', (req, res) => {
  const f = req.params.file;
  if (!/^[a-f0-9]{32}\.[a-z0-9]{2,5}$/.test(f)) return res.sendStatus(404);
  const ext = f.split('.')[1];
  const opts = { maxAge: '365d', immutable: true, headers: {} };
  if (MIME[ext]) opts.headers['Content-Type'] = MIME[ext];
  else { opts.headers['Content-Type'] = 'application/octet-stream'; opts.headers['Content-Disposition'] = 'attachment'; }
  res.sendFile(path.join(UP_DIR, f), opts, err => { if (err && !res.headersSent) res.sendStatus(404); });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => res.status(400).json({ error: 'Неверный запрос' }));

/* ---------- сокеты ---------- */
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: MAX_FILE + 512 * 1024 });

io.use((socket, next) => {
  const u = userByToken(socket.handshake.auth && socket.handshake.auth.token);
  if (!u) return next(new Error('auth'));
  socket.data.uid = u.id;
  next();
});

function take(s, cost = 1) {
  const t = now(); const b = s.data.bucket || (s.data.bucket = { n: 20, t });
  b.n = Math.min(20, b.n + (t - b.t) / 500); b.t = t;
  if (b.n < cost) return false;
  b.n -= cost; return true;
}

function post(from, to, body) {
  const m = { ...body, id: ++db.seq, from: from.id, to: to.id, ts: now(), st: isOn(to.id) ? 1 : 0 };
  const k = chatKey(from.id, to.id);
  (db.chats[k] || (db.chats[k] = [])).push(m);
  link(from.id, to.id);
  save();
  io.to(to.id).emit('msg', { m, user: pub(from) });
  io.to(from.id).emit('msg', { m, user: pub(to) });
  return m;
}
const pushSelf = (...users) => users.forEach(u => io.to(u.id).emit('me', selfView(u)));
const presence = uid => {
  const u = db.users[uid];
  for (const pid of peers.get(uid) || []) io.to(pid).emit('presence', { id: uid, online: isOn(uid), last: u.last || 0 });
};
function chatList(uid) {
  const out = [];
  for (const pid of peers.get(uid) || []) {
    const p = db.users[pid]; if (!p) continue;
    const arr = db.chats[chatKey(uid, pid)] || [];
    let unread = 0;
    for (let i = arr.length - 1; i >= 0; i--) { const m = arr[i]; if (m.to === uid) { if (m.st >= 2) break; unread++; } }
    out.push({ user: pub(p), last: arr[arr.length - 1] || null, unread });
  }
  return out.sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));
}
function markDelivered(uid) {
  for (const pid of peers.get(uid) || []) {
    const arr = db.chats[chatKey(uid, pid)] || []; let ch = false;
    for (let i = arr.length - 1; i >= 0; i--) { const m = arr[i]; if (m.to === uid) { if (m.st >= 1) break; m.st = 1; ch = true; } }
    if (ch) io.to(pid).emit('delivered', { by: uid });
  }
  save();
}

io.on('connection', socket => {
  const uid = socket.data.uid;
  socket.join(uid); // единственная комната, в которую попадает клиент — его собственная
  if (!online.has(uid)) online.set(uid, new Set());
  online.get(uid).add(socket.id);
  if (online.get(uid).size === 1) { presence(uid); markDelivered(uid); }

  socket.on('disconnect', () => {
    const set = online.get(uid); if (!set) return;
    set.delete(socket.id);
    if (!set.size) { online.delete(uid); if (db.users[uid]) { db.users[uid].last = now(); save(); presence(uid); } }
  });

  const on = (ev, fn, cost = 1) => socket.on(ev, async (data, cb) => {
    if (typeof cb !== 'function') cb = () => {};
    if (!take(socket, cost)) return cb({ error: 'Слишком часто, подождите секунду' });
    const me = db.users[uid]; if (!me) return cb({ error: 'auth' });
    try { const r = await fn(data && typeof data === 'object' ? data : {}, me); cb(r || {}); }
    catch (e) { if (!e.userMessage) console.error(ev, e); cb({ error: e.userMessage || 'Ошибка сервера' }); }
  });
  const peerOf = (id, me) => {
    if (!hasUser(id)) fail('Пользователь не найден');
    if (id === me.id) fail('Нельзя выбрать самого себя');
    return db.users[id];
  };

  on('bootstrap', (_, me) => ({ me: selfView(me), chats: chatList(me.id), gifts: catalog(), daily: DAILY_STARS }));

  on('search', ({ q }, me) => {
    q = normUser(q); if (!q) return { users: [] };
    const hit = [];
    for (const [un, id] of byName) if (id !== me.id && un.includes(q)) hit.push(un);
    hit.sort((a, b) => (b.startsWith(q) - a.startsWith(q)) || a.length - b.length);
    return { users: hit.slice(0, 20).map(un => pub(db.users[byName.get(un)])) };
  });

  on('user', ({ id, username }, me) => {
    const u = id ? (hasUser(id) ? db.users[id] : null) : (byName.has(normUser(username)) ? db.users[byName.get(normUser(username))] : null);
    if (!u) fail('Пользователь не найден');
    const gifts = Object.values(db.items).filter(i => i.owner === u.id).sort((a, b) => b.ts - a.ts);
    return { user: pub(u), gifts: gifts.slice(0, 60), giftsTotal: gifts.length };
  });

  on('history', ({ peer, before }, me) => {
    const p = peerOf(peer, me);
    const arr = db.chats[chatKey(me.id, p.id)] || [];
    let end = arr.length;
    if (before) { end = arr.findIndex(m => m.id >= before); if (end < 0) end = arr.length; }
    const start = Math.max(0, end - 40);
    return { msgs: arr.slice(start, end), more: start > 0, user: pub(p) };
  });

  on('send', ({ peer, text }, me) => {
    const p = peerOf(peer, me);
    text = String(text || '').trim();
    if (!text) fail('Пустое сообщение');
    if (text.length > 4000) fail('Сообщение слишком длинное');
    post(me, p, { t: 'text', text });
    return {};
  });

  const IMG = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp' };
  const AUD = { 'audio/webm': 'webm', 'audio/ogg': 'ogg', 'audio/mp4': 'm4a', 'audio/mpeg': 'mp3', 'audio/aac': 'aac', 'audio/x-m4a': 'm4a' };
  on('send_media', async ({ peer, kind, name, mime, dur, data }, me) => {
    const p = peerOf(peer, me);
    if (data instanceof ArrayBuffer) data = Buffer.from(data);
    if (!Buffer.isBuffer(data) || !data.length) fail('Нет данных файла');
    if (data.length > MAX_FILE) fail('Файл больше 8 МБ');
    mime = String(mime || '').split(';')[0].toLowerCase();
    let ext = 'bin', t = 'file';
    if (kind === 'image' && IMG[mime] && sniffImg(data, IMG[mime])) { ext = IMG[mime]; t = 'image'; }
    else if (kind === 'voice' && AUD[mime]) { ext = AUD[mime]; t = 'voice'; }
    const fid = crypto.randomBytes(16).toString('hex') + '.' + ext;
    await fs.promises.writeFile(path.join(UP_DIR, fid), data);
    name = String(name || 'file').replace(/[\\/\u0000-\u001f]/g, '_').slice(0, 120);
    post(me, p, { t, url: '/f/' + fid, name, size: data.length, ...(t === 'voice' ? { dur: Math.min(3600, Math.max(0, +dur || 0)) } : {}) });
    return {};
  }, 3);

  on('read', ({ peer }, me) => {
    const p = peerOf(peer, me);
    const arr = db.chats[chatKey(me.id, p.id)] || []; let ch = false;
    for (let i = arr.length - 1; i >= 0; i--) { const m = arr[i]; if (m.to === me.id) { if (m.st >= 2) break; m.st = 2; ch = true; } }
    if (ch) { save(); io.to(p.id).emit('read', { by: me.id }); io.to(me.id).emit('read_self', { peer: p.id }); }
    return {};
  }, 0.3);

  on('typing', ({ peer }, me) => { if (hasUser(peer) && peer !== me.id) io.to(peer).emit('typing', { from: me.id }); return {}; }, 0.5);

  on('profile:set', async (d, me) => {
    if ('name' in d) { const n = String(d.name).trim().slice(0, 40); if (!n) fail('Имя не может быть пустым'); me.name = n; }
    if ('bio' in d) me.bio = String(d.bio).trim().slice(0, 140);
    if ('accent' in d) { const a = d.accent | 0; if (a >= 0 && a < 8) me.accent = a; }
    if ('username' in d) {
      const un = normUser(d.username);
      if (un !== me.username) {
        if (!USER_RE.test(un)) fail(USER_MSG);
        if (byName.has(un)) fail('Юзернейм занят');
        byName.delete(me.username); byName.set(un, me.id); me.username = un;
      }
    }
    if (d.avatar === null) {
      if (me.av) fs.unlink(path.join(AV_DIR, me.id + '.' + me.avx), () => {});
      me.av = 0;
    } else if (typeof d.avatar === 'string') {
      const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(d.avatar);
      if (!m) fail('Неверное изображение');
      const buf = Buffer.from(m[2], 'base64'); const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
      if (buf.length > 300 * 1024) fail('Аватар слишком большой');
      if (!sniffImg(buf, ext)) fail('Неверное изображение');
      if (me.av && me.avx !== ext) fs.unlink(path.join(AV_DIR, me.id + '.' + me.avx), () => {});
      await fs.promises.writeFile(path.join(AV_DIR, me.id + '.' + ext), buf);
      me.avx = ext; me.av = now();
    }
    save();
    io.to(me.id).emit('me', selfView(me));
    for (const pid of peers.get(me.id) || []) io.to(pid).emit('user_update', pub(me));
    return { me: selfView(me) };
  });

  on('gift:send', ({ peer, gid, note }, me) => {
    const p = peerOf(peer, me);
    const g = GIFTS.find(x => x.id === gid); if (!g) fail('Нет такого подарка');
    const minted = db.minted[g.id] || 0;
    if (g.supply && minted >= g.supply) fail('Этот подарок закончился');
    if (me.stars < g.price) fail('Не хватает звёзд');
    me.stars -= g.price; db.minted[g.id] = minted + 1;
    const item = { id: 'n' + crypto.randomBytes(5).toString('hex'), gid: g.id, name: g.name, emoji: g.emoji, num: minted + 1, sup: g.supply, bg: crypto.randomInt(10), sym: crypto.randomInt(6), rar: rollRarity(), owner: p.id, from: me.id, ts: now() };
    db.items[item.id] = item;
    post(me, p, { t: 'gift', item: { ...item }, text: String(note || '').trim().slice(0, 100) });
    pushSelf(me);
    return { stars: me.stars };
  });

  on('stars:send', ({ peer, amount }, me) => {
    const p = peerOf(peer, me);
    const n = Math.floor(+amount);
    if (!(n >= 1 && n <= 100000)) fail('Некорректная сумма');
    if (me.stars < n) fail('Не хватает звёзд');
    me.stars -= n; p.stars += n;
    post(me, p, { t: 'stars', stars: n });
    pushSelf(me, p);
    return { stars: me.stars };
  });

  on('stars:daily', (_, me) => {
    const wait = 864e5 - (now() - (me.lastDaily || 0));
    if (wait > 0) return { error: 'Бонус уже получен', wait };
    me.lastDaily = now(); me.stars += DAILY_STARS; save(); pushSelf(me);
    return { stars: me.stars };
  });
});

server.listen(PORT, '0.0.0.0', () => console.log('ZadrottzGram: http://localhost:' + PORT));
