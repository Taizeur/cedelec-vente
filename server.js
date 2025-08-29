// Cedelec Vente – application complète en un seul fichier
// Stack : Node.js + Express + SQLite3 + express-session + connect-sqlite3 + Multer (upload images) + Socket.IO (chat)
// Objectif :
// - Catalogue d'objets (ajout d'articles avec photos, description, prix)
// - Comptes simples (inscription/connexion par nom d'utilisateur + mot de passe)
// - Pas d'achat en ligne ; uniquement une messagerie (chat) par annonce
// - Tableau de bord admin (ajout d'objets + vue de toutes les conversations)
//
// Pour démarrer :
//   1) mkdir cedelec-vente && cd cedelec-vente
//   2) npm init -y
//   3) npm i express sqlite3 bcrypt express-session connect-sqlite3 multer socket.io
//   4) node server.js
//   5) Ouvrez http://localhost:3000
//
// Par défaut, un compte admin est créé au premier lancement :
//   identifiant : admin
//   mot de passe : changeme
// Pensez à le changer (menu -> Mon compte) !

const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const { Server } = require('socket.io');

// ------------------------------------------------------------
// Initialisation
// ------------------------------------------------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Sessions
const sessionMiddleware = session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: 'remplacez-moi-par-un-secret-plus-long',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }, // 30 jours
});
app.use(sessionMiddleware);

// Partager la session avec Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/static', express.static(path.join(__dirname, 'public')));

// Multer (upload d'images)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeBase = path.basename(file.originalname, ext).replace(/[^a-z0-9-_]+/gi, '_');
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2, 8)}_${safeBase}${ext}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  },
  limits: { fileSize: 6 * 1024 * 1024, files: 6 }, // max 6 Mo par fichier, 6 fichiers
});

// ------------------------------------------------------------
// Base de données
// ------------------------------------------------------------
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    images_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'available',
    created_at TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    UNIQUE(item_id, user_id),
    FOREIGN KEY(item_id) REFERENCES items(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(conversation_id) REFERENCES conversations(id),
    FOREIGN KEY(sender_id) REFERENCES users(id)
  )`);

  // Création d'un admin par défaut si inexistant
  db.get(`SELECT COUNT(*) as c FROM users WHERE role='admin'`, async (err, row) => {
    if (err) return console.error(err);
    if (row.c === 0) {
      const hash = await bcrypt.hash('changeme', 10);
      db.run(
        `INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?, 'admin', ?)`,
        ['admin', hash, new Date().toISOString()],
        (e) => {
          if (e) console.error(e);
          else console.log('\n>>> Compte admin initial créé : identifiant "admin" / mot de passe "changeme"');
        }
      );
    }
  });
});

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send(renderLayout('Accès refusé', `<div class="p">Accès réservé à l’administrateur.</div>`));
  next();
}
function isLogged(req) {
  return !!(req.session && req.session.user);
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
}

// ------------------------------------------------------------
// Rendu HTML minimaliste (pas de moteur de template externe)
// ------------------------------------------------------------
function renderLayout(title, content, opts = {}) {
  const user = opts.user;
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${esc(title)} – Cedelec Vente</title>
  <style>
    :root{--bg:#0f172a;--panel:#111827;--muted:#94a3b8;--text:#e5e7eb;--brand:#38bdf8;--accent:#22c55e;}
    *{box-sizing:border-box} body{margin:0;background:linear-gradient(180deg,#0b1220,#0f172a);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif}
    header{position:sticky;top:0;backdrop-filter:blur(4px);background:rgba(15,23,42,.8);border-bottom:1px solid #1f2937}
    .wrap{max-width:1100px;margin:0 auto;padding:12px 16px}
    .brand{font-weight:700;letter-spacing:.2px}
    nav a{color:var(--muted);text-decoration:none;margin-right:14px}
    nav a:hover{color:var(--text)}
    .btn{display:inline-block;border-radius:12px;border:1px solid #334155;padding:10px 14px;text-decoration:none;color:var(--text);background:#0b1324}
    .btn:hover{border-color:#64748b}
    .btn.primary{background:linear-gradient(135deg,#0891b2,#38bdf8);border-color:transparent;color:#001018}
    .grid{display:grid;gap:16px}
    .grid.cards{grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
    .card{background:rgba(17,24,39,.8);border:1px solid #1f2937;border-radius:16px;overflow:hidden}
    .card .thumb{aspect-ratio:4/3;object-fit:cover;width:100%;background:#0a0f1c}
    .card .pad{padding:12px}
    .price{font-weight:700}
    .muted{color:var(--muted)}
    .p{padding:16px}
    form .row{display:flex;gap:12px;flex-wrap:wrap}
    form label{display:block;font-size:14px;margin:8px 0 6px}
    input[type=text], input[type=password], input[type=number], textarea{width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#0b1324;color:var(--text)}
    textarea{min-height:120px}
    .footer{color:#64748b;font-size:13px;padding:24px 0}
    .badge{font-size:12px;padding:4px 8px;border:1px solid #334155;border-radius:999px;color:#cbd5e1}
    .row.center{align-items:center}
    .flex{display:flex;gap:10px}
    .right{margin-left:auto}
    .table{width:100%;border-collapse:collapse}
    .table th,.table td{border-bottom:1px solid #1f2937;padding:10px;text-align:left}
    .chatbox{position:fixed;right:16px;bottom:16px;width:340px;max-width:90vw;border:1px solid #1f2937;border-radius:16px;overflow:hidden;background:#111827;display:none}
    .chatheader{padding:10px 12px;background:#0b1324;border-bottom:1px solid #1f2937}
    .chatlog{height:280px;overflow:auto;padding:10px;display:flex;flex-direction:column;gap:8px}
    .msg{max-width:85%;padding:8px 10px;border-radius:12px}
    .me{align-self:flex-end;background:linear-gradient(135deg,#059669,#22c55e)}
    .them{align-self:flex-start;background:#1f2937}
    .chatinput{display:flex;gap:8px;padding:10px;border-top:1px solid #1f2937}
    .fab{position:fixed;right:16px;bottom:16px;width:54px;height:54px;border-radius:999px;background:linear-gradient(135deg,#0891b2,#38bdf8);display:flex;align-items:center;justify-content:center;border:none;color:#001018;font-size:24px;cursor:pointer}
    .hide{display:none}
    .tag{display:inline-block;background:#172554;border:1px solid #1f3a5f;padding:4px 8px;border-radius:10px;font-size:12px}
  </style>
</head>
<body>
  <header>
    <div class="wrap flex row center">
      <div class="brand">⚡ Cedelec Vente</div>
      <nav class="right">
        <a href="/">Catalogue</a>
        ${user && user.role==='admin' ? '<a href="/admin">Admin</a>' : ''}
        ${user ? `<span class="badge">Connecté : ${esc(user.username)}${user.role==='admin'?' (admin)':''}</span> <a class="btn" href="/account">Mon compte</a> <a class="btn" href="/logout">Déconnexion</a>` : `<a class="btn" href="/login">Connexion</a> <a class="btn primary" href="/register">Créer un compte</a>`}
      </nav>
    </div>
  </header>
  <main>
    <div class="wrap">${content}</div>
  </main>
  <div class="footer wrap">&copy; ${new Date().getFullYear()} – Cedelec Vente. Pas de paiement en ligne : prise de contact uniquement.</div>
  <script src="/socket.io/socket.io.js"></script>
</body>
</html>`;
}

// ------------------------------------------------------------
// Pages publiques
// ------------------------------------------------------------
app.get('/', (req, res) => {
  const q = (req.query.q || '').trim();
  const params = [];
  let sql = 'SELECT * FROM items WHERE status="available"';
  if (q) { sql += ' AND (title LIKE ? OR description LIKE ?)'; params.push('%'+q+'%', '%'+q+'%'); }
  sql += ' ORDER BY id DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).send('Erreur DB');
    const cards = rows.map(it => {
      const images = JSON.parse(it.images_json||'[]');
      const img = images[0] ? `/uploads/${esc(images[0])}` : 'https://via.placeholder.com/720x540?text=Photo';
      return `<div class="card">
        <img class="thumb" src="${img}" alt="${esc(it.title)}">
        <div class="pad">
          <div style="font-weight:700;margin-bottom:4px">${esc(it.title)}</div>
          <div class="muted" style="min-height:36px">${esc(it.description).slice(0,90)}${it.description.length>90?'…':''}</div>
          <div class="flex" style="margin-top:10px;align-items:center">
            <span class="price">${Number(it.price).toFixed(2)} €</span>
            <a class="btn right" href="/item/${it.id}">Voir</a>
          </div>
        </div>
      </div>`;
    }).join('');

    const content = `
      <form method="get" class="p">
        <label for="q">Recherche</label>
        <div class="row">
          <input type="text" id="q" name="q" placeholder="Objet, mot-clé…" value="${esc(q)}" />
          <button class="btn">Rechercher</button>
        </div>
      </form>
      <div class="grid cards">${cards || '<div class="p muted">Aucun article pour le moment.</div>'}</div>
    `;
    res.send(renderLayout('Catalogue', content, { user: req.session.user }));
  });
});

app.get('/item/:id', (req, res) => {
  db.get('SELECT * FROM items WHERE id=?', [req.params.id], (err, it) => {
    if (err || !it) return res.status(404).send(renderLayout('Introuvable', '<div class="p">Article introuvable.</div>', {user:req.session.user}));
    const images = JSON.parse(it.images_json||'[]');
    const gallery = images.map(fn => `<img class="thumb" src="/uploads/${esc(fn)}" alt="${esc(it.title)}">`).join('');
    const content = `
      <div class="grid" style="grid-template-columns: 1.2fr .8fr; gap:22px">
        <div>
          <div class="grid" style="grid-template-columns: 1fr 1fr; gap:12px">${gallery || '<div class="card p">Aucune photo</div>'}</div>
        </div>
        <div>
          <div class="card"><div class="pad">
            <h1 style="margin:0 0 8px 0">${esc(it.title)}</h1>
            <div class="price" style="font-size:22px">${Number(it.price).toFixed(2)} €</div>
            <p class="muted" style="margin:8px 0 16px 0;white-space:pre-wrap">${esc(it.description)}</p>
            <div class="tag">Pas d’achat en ligne • Contact via chat</div>
          </div></div>
        </div>
      </div>

      <button class="fab" id="openChat" title="Discuter de cet objet">💬</button>
      <div class="chatbox" id="chatBox">
        <div class="chatheader">Discussion à propos de « ${esc(it.title)} »</div>
        <div class="chatlog" id="chatLog"></div>
        <div class="chatinput">
          <input type="text" id="chatMsg" placeholder="Votre message…" />
          <button class="btn primary" id="sendBtn">Envoyer</button>
        </div>
      </div>

      <script>
        const userLogged = ${JSON.stringify(!!req.session.user)};
        const nextUrl = ${JSON.stringify('/item/' + it.id)};
        const itemId = ${it.id};
        const openBtn = document.getElementById('openChat');
        const box = document.getElementById('chatBox');
        const log = document.getElementById('chatLog');
        const input = document.getElementById('chatMsg');
        const sendBtn = document.getElementById('sendBtn');
        let convoId = null;
        let socket = null;

        function appendMsg(m){
          const div = document.createElement('div');
          div.className = 'msg ' + (m.mine ? 'me' : 'them');
          div.textContent = m.body;
          log.appendChild(div); log.scrollTop = log.scrollHeight;
        }

        async function startConversation(){
          const r = await fetch('/api/conversations/start', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ item_id: itemId })});
          if (!r.ok){ if(r.status===401) { window.location = '/login?next='+encodeURIComponent(nextUrl); return; } throw new Error('start failed'); }
          const data = await r.json(); convoId = data.conversation_id; box.style.display = 'block';

          const r2 = await fetch('/api/conversations/'+convoId+'/messages');
          const msgs = await r2.json();
          log.innerHTML='';
          msgs.forEach(m => appendMsg({ body: m.body, mine: m.mine }));

          socket = io();
          socket.emit('join', { conversation_id: convoId });
          socket.on('message', (m) => { appendMsg({ body: m.body, mine: m.mine }); });
        }

        openBtn.addEventListener('click', () => {
          if(!userLogged){ window.location = '/login?next='+encodeURIComponent(nextUrl); return; }
          if(!convoId) startConversation(); else box.style.display = (box.style.display==='none'||!box.style.display)?'block':'none';
        });
        sendBtn.addEventListener('click', async () => {
          const body = input.value.trim(); if(!body) return; input.value='';
          const r = await fetch('/api/conversations/'+convoId+'/messages', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ body })});
          if(!r.ok) return alert('Erreur envoi');
        });
        input.addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ sendBtn.click(); } });
      </script>
    `;
    res.send(renderLayout(it.title, content, { user: req.session.user }));
  });
});

// ------------------------------------------------------------
// Authentification
// ------------------------------------------------------------
app.get('/register', (req, res) => {
  const content = `
    <div class="card"><div class="pad">
      <h2>Créer un compte</h2>
      <form method="post" action="/register">
        <label>Nom d'utilisateur</label>
        <input type="text" name="username" required>
        <label>Mot de passe</label>
        <input type="password" name="password" required>
        <div style="margin-top:12px" class="flex">
          <button class="btn primary">Créer</button>
          <a class="btn" href="/login">Déjà inscrit ? Connexion</a>
        </div>
      </form>
    </div></div>`;
  res.send(renderLayout('Créer un compte', content, { user: req.session.user }));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Champs requis');
  bcrypt.hash(password, 10).then(hash => {
    db.run(`INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)`,
      [username.trim(), hash, new Date().toISOString()], (err) => {
        if (err) return res.send(renderLayout('Créer un compte', `<div class="p">Nom d'utilisateur indisponible.</div>`, {user:req.session.user}));
        db.get(`SELECT id, username, role FROM users WHERE username=?`, [username.trim()], (e,row)=>{
          req.session.user = row; res.redirect('/');
        });
      });
  });
});

app.get('/login', (req, res) => {
  const next = req.query.next || '/';
  const content = `
    <div class="card"><div class="pad">
      <h2>Connexion</h2>
      <form method="post" action="/login">
        <input type="hidden" name="next" value="${esc(next)}">
        <label>Nom d'utilisateur</label>
        <input type="text" name="username" required>
        <label>Mot de passe</label>
        <input type="password" name="password" required>
        <div style="margin-top:12px" class="flex">
          <button class="btn primary">Se connecter</button>
          <a class="btn" href="/register">Créer un compte</a>
        </div>
      </form>
    </div></div>`;
  res.send(renderLayout('Connexion', content, { user: req.session.user }));
});

app.post('/login', (req, res) => {
  const { username, password, next } = req.body;
  db.get(`SELECT * FROM users WHERE username=?`, [username], (err, user) => {
    if (err || !user) return res.send(renderLayout('Connexion', '<div class="p">Identifiants invalides.</div>', {user:req.session.user}));
    bcrypt.compare(password, user.password_hash).then(ok => {
      if (!ok) return res.send(renderLayout('Connexion', '<div class="p">Identifiants invalides.</div>', {user:req.session.user}));
      req.session.user = { id: user.id, username: user.username, role: user.role };
      res.redirect(next || '/');
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(()=> res.redirect('/'));
});

app.get('/account', requireAuth, (req, res) => {
  const content = `
    <div class="card"><div class="pad">
      <h2>Mon compte</h2>
      <p class="muted">Connecté en tant que <strong>${esc(req.session.user.username)}</strong>${req.session.user.role==='admin'?' (admin)':''}</p>
      <h3>Modifier le mot de passe</h3>
      <form method="post" action="/account/password">
        <label>Nouveau mot de passe</label>
        <input type="password" name="password" required>
        <div style="margin-top:12px"><button class="btn primary">Mettre à jour</button></div>
      </form>
    </div></div>`;
  res.send(renderLayout('Mon compte', content, { user: req.session.user }));
});

app.post('/account/password', requireAuth, (req, res) => {
  const { password } = req.body;
  bcrypt.hash(password, 10).then(hash => {
    db.run(`UPDATE users SET password_hash=? WHERE id=?`, [hash, req.session.user.id], (err) => {
      if (err) return res.status(500).send('Erreur DB');
      res.redirect('/account');
    });
  });
});

// ------------------------------------------------------------
// API conversations/messages (utilisées par le chat)
// ------------------------------------------------------------
app.post('/api/conversations/start', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'not_logged_in' });
  const userId = req.session.user.id;
  const { item_id } = req.body;
  if (!item_id) return res.status(400).json({ error: 'missing_item' });
  db.get(`SELECT id FROM conversations WHERE item_id=? AND user_id=?`, [item_id, userId], (err, row) => {
    if (row) return res.json({ conversation_id: row.id });
    db.run(`INSERT INTO conversations (item_id, user_id, created_at) VALUES (?,?,?)`, [item_id, userId, new Date().toISOString()], function(e){
      if (e) return res.status(500).json({ error: 'db' });
      return res.json({ conversation_id: this.lastID });
    });
  });
});

app.get('/api/conversations/:id/messages', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'not_logged_in' });
  const cid = Number(req.params.id);
  // Vérifier que l'utilisateur a le droit (auteur OU admin)
  db.get(`SELECT * FROM conversations WHERE id=?`, [cid], (err, conv) => {
    if (err || !conv) return res.status(404).json({ error: 'not_found' });
    if (req.session.user.role !== 'admin' && conv.user_id !== req.session.user.id) return res.status(403).json({ error: 'forbidden' });
    db.all(`SELECT m.*, (m.sender_id=?) AS mine FROM messages m WHERE m.conversation_id=? ORDER BY m.id ASC`, [req.session.user.id, cid], (e, rows) => {
      if (e) return res.status(500).json({ error: 'db' });
      res.json(rows.map(r=>({ id:r.id, body:r.body, mine:!!r.mine, created_at:r.created_at })));
    });
  });
});

app.post('/api/conversations/:id/messages', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'not_logged_in' });
  const cid = Number(req.params.id);
  const body = (req.body.body||'').trim();
  if (!body) return res.status(400).json({ error: 'empty' });
  db.get(`SELECT * FROM conversations WHERE id=?`, [cid], (err, conv) => {
    if (err || !conv) return res.status(404).json({ error: 'not_found' });
    if (req.session.user.role !== 'admin' && conv.user_id !== req.session.user.id) return res.status(403).json({ error: 'forbidden' });
    db.run(`INSERT INTO messages (conversation_id, sender_id, body, created_at) VALUES (?,?,?,?)`, [cid, req.session.user.id, body, new Date().toISOString()], function(e){
      if (e) return res.status(500).json({ error: 'db' });
      // Broadcast temps réel dans la room
      io.to('convo_'+cid).emit('message', { id: this.lastID, body, mine: false, created_at: new Date().toISOString() });
      res.json({ ok:true });
    });
  });
});

// ------------------------------------------------------------
// Espace Admin
// ------------------------------------------------------------
app.get('/admin', requireAdmin, (req, res) => {
  // Récap rapide : nb articles, nb conversations
  db.get(`SELECT COUNT(*) c FROM items`, (e1, r1) => {
    db.get(`SELECT COUNT(*) c FROM conversations`, (e2, r2) => {
      const content = `
        <div class="grid" style="grid-template-columns: 1fr 1fr; gap:16px">
          <div class="card"><div class="pad">
            <div class="muted">Articles</div>
            <div style="font-size:32px;font-weight:800">${r1.c||0}</div>
            <div style="margin-top:8px"><a class="btn primary" href="/admin/items/new">Ajouter un article</a> <a class="btn" href="/admin/items">Gérer</a></div>
          </div></div>
          <div class="card"><div class="pad">
            <div class="muted">Conversations</div>
            <div style="font-size:32px;font-weight:800">${r2.c||0}</div>
            <div style="margin-top:8px"><a class="btn" href="/admin/conversations">Ouvrir les discussions</a></div>
          </div></div>
        </div>`;
      res.send(renderLayout('Admin', content, { user: req.session.user }));
    });
  });
});

app.get('/admin/items', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM items ORDER BY id DESC`, (err, rows) => {
    const trs = rows.map(it => {
      const first = (JSON.parse(it.images_json||'[]')[0]||'');
      return `<tr>
        <td>${it.id}</td>
        <td>${esc(it.title)}</td>
        <td>${Number(it.price).toFixed(2)} €</td>
        <td>${esc(it.status)}</td>
        <td>${first?`<img src="/uploads/${esc(first)}" style="height:40px;border-radius:6px">`:''}</td>
        <td><a class="btn" href="/item/${it.id}" target="_blank">Voir</a></td>
      </tr>`;
    }).join('');
    const content = `
      <div class="flex" style="margin-bottom:10px"><a class="btn primary" href="/admin/items/new">Ajouter</a></div>
      <table class="table"><thead><tr><th>ID</th><th>Titre</th><th>Prix</th><th>Statut</th><th>Photo</th><th></th></tr></thead><tbody>${trs}</tbody></table>`;
    res.send(renderLayout('Gérer les articles', content, { user: req.session.user }));
  });
});

app.get('/admin/items/new', requireAdmin, (req, res) => {
  const content = `
    <div class="card"><div class="pad">
      <h2>Ajouter un article</h2>
      <form method="post" action="/admin/items" enctype="multipart/form-data">
        <div class="row">
          <div style="flex:1">
            <label>Titre</label>
            <input type="text" name="title" required>
          </div>
          <div style="width:160px">
            <label>Prix (€)</label>
            <input type="number" name="price" step="0.01" min="0" required>
          </div>
        </div>
        <label>Description</label>
        <textarea name="description" required></textarea>
        <label>Photos (jusqu’à 6)</label>
        <input type="file" name="images" multiple accept="image/*">
        <div style="margin-top:12px"><button class="btn primary">Publier</button></div>
      </form>
    </div></div>`;
  res.send(renderLayout('Ajouter un article', content, { user: req.session.user }));
});

app.post('/admin/items', requireAdmin, upload.array('images', 6), (req, res) => {
  const { title, description, price } = req.body;
  const files = (req.files||[]).map(f=>path.basename(f.path));
  db.run(`INSERT INTO items (title, description, price, images_json, created_at) VALUES (?,?,?,?,?)`,
    [title, description, Number(price||0), JSON.stringify(files), new Date().toISOString()],
    function(err){ if(err) return res.status(500).send('Erreur DB'); res.redirect('/admin/items'); }
  );
});

app.get('/admin/conversations', requireAdmin, (req, res) => {
  const sql = `SELECT c.id, c.created_at, u.username, i.title as item_title
               FROM conversations c
               JOIN users u ON u.id = c.user_id
               JOIN items i ON i.id = c.item_id
               ORDER BY c.id DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).send('Erreur DB');
    const lis = rows.map(r => `<tr><td>${r.id}</td><td>${esc(r.username)}</td><td>${esc(r.item_title)}</td><td><a class="btn" href="/admin/conversations/${r.id}">Ouvrir</a></td></tr>`).join('');
    const content = `
      <table class="table">
        <thead><tr><th>ID</th><th>Utilisateur</th><th>Article</th><th></th></tr></thead>
        <tbody>${lis}</tbody>
      </table>`;
    res.send(renderLayout('Conversations', content, { user: req.session.user }));
  });
});

app.get('/admin/conversations/:id', requireAdmin, (req, res) => {
  const cid = Number(req.params.id);
  const content = `
    <div class="card"><div class="pad">
      <h2>Discussion #${cid}</h2>
      <div id="chatLog" class="chatlog" style="height:380px"></div>
      <div class="chatinput"><input id="msg" type="text" placeholder="Répondre…"><button id="send" class="btn primary">Envoyer</button></div>
    </div></div>
    <script>
      const cid = ${cid};
      const log = document.getElementById('chatLog');
      const input = document.getElementById('msg');
      const send = document.getElementById('send');
      function append(m){ const d=document.createElement('div'); d.className='msg '+(m.mine?'me':'them'); d.textContent=m.body; log.appendChild(d); log.scrollTop=log.scrollHeight; }
      (async ()=>{
        const r = await fetch('/api/conversations/'+cid+'/messages');
        const msgs = await r.json(); msgs.forEach(append);
        const s = io(); s.emit('join', { conversation_id: cid }); s.on('message', append);
        send.onclick = async ()=>{ const body = input.value.trim(); if(!body) return; input.value=''; await fetch('/api/conversations/'+cid+'/messages', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ body }) }); };
        input.addEventListener('keydown',(e)=>{ if(e.key==='Enter') send.click(); });
      })();
    </script>
  `;
  res.send(renderLayout('Conversation', content, { user: req.session.user }));
});

// ------------------------------------------------------------
// Socket.IO – rooms par conversation
// ------------------------------------------------------------
io.on('connection', (socket) => {
  const sess = socket.request.session;
  socket.on('join', ({ conversation_id }) => {
    if (!sess || !sess.user) return; // ignore
    // petit contrôle d'accès : l'utilisateur doit être admin ou membre de la conversation
    db.get(`SELECT * FROM conversations WHERE id=?`, [conversation_id], (err, conv) => {
      if (err || !conv) return; // ignore
      if (sess.user.role !== 'admin' && conv.user_id !== sess.user.id) return; // refuse
      socket.join('convo_'+conversation_id);
    });
  });
});

// ------------------------------------------------------------
// 404
// ------------------------------------------------------------
app.use((req, res) => {
  res.status(404).send(renderLayout('404', '<div class="p">Page introuvable.</div>', { user: req.session.user }));
});

// ------------------------------------------------------------
// Lancement
// ------------------------------------------------------------
server.listen(PORT, () => {
  console.log(`Cedelec Vente en ligne sur http://localhost:${PORT}`);
});
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.sqlite');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
