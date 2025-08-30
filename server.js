// Cedelec Vente – serveur complet (Render gratuit, stockage /tmp)
// Stack: Express + SQLite + Sessions + Multer (uploads) + Socket.IO (chat)

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const http = require("http");
const { Server } = require("socket.io");

// ---------- Config (Render gratuit : tout dans /tmp) ----------
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "/tmp/data.sqlite";
const UPLOAD_DIR = process.env.UPLOAD_DIR || "/tmp/uploads";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-please";

// crée le dossier d’uploads si besoin
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- Base de données (SQLite) ----------
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    images_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'available',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(item_id, user_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Création d'un admin par défaut si absent
  db.get(`SELECT COUNT(*) AS c FROM users WHERE role='admin'`, async (err, row) => {
    if (err) return console.error(err);
    if ((row?.c || 0) === 0) {
      const hash = await bcrypt.hash("changeme", 10);
      db.run(
        `INSERT INTO users (username, password_hash, role) VALUES (?,?,?)`,
        ["admin", hash, "admin"],
        (e) => {
          if (e) console.error(e);
          else console.log('>>> Compte admin créé : identifiant "admin" / mot de passe "changeme"');
        }
      );
    }
  });
});

// ---------- App/Server/Socket ----------
const app = express();              // <= UNE seule initialisation !
const server = http.createServer(app);
const io = new Server(server);

// ---------- Middlewares ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // sert /public (style.css, logo…)
app.use("/uploads", express.static(UPLOAD_DIR));         // sert les photos uploadées

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: path.dirname(DB_FILE) }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }, // 30 jours
  })
);

// ---------- Multer (uploads -> /tmp/uploads) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const base = path.basename(file.originalname, ext).replace(/[^a-z0-9-_]+/gi, "_");
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2, 8)}_${base}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024, files: 6 },
});

// ---------- Helpers ----------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Accès admin requis.");
  next();
}
function esc(s) {
  return String(s).replace(/[&<>\"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- Layout (header + footer + CSS) ----------
function page(title, content, user) {
  return `
  <!doctype html>
  <html lang="fr">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>${esc(title)}</title>
    <link rel="stylesheet" href="/style.css">
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="brand">Cedelec Vente</div>
        <div>
          ${user ? `<span class="badge">Connecté : ${esc(user.username)}</span> <a class="btn secondary" href="/logout">Déconnexion</a>` :
            `<a class="btn secondary" href="/login">Connexion</a> <a class="btn" href="/register">Créer un compte</a>`}
          ${user?.role === "admin" ? ` <a class="btn" href="/admin">Admin</a>` : ""}
        </div>
      </div>
      ${content}
      <div class="footer">SARL Cedelec – 5 route de Crochte, 59380 Socx</div>
    </div>
  </body>
  </html>`;
}

// ---------- Routes publiques ----------
app.get("/", (req, res) => {
  db.all(`SELECT * FROM items WHERE status='available' ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).send("Erreur DB");
    const cards = (rows || [])
      .map((it) => {
        const imgs = JSON.parse(it.images_json || "[]");
        const img = imgs[0] ? `<img class="item-img" src="${esc(imgs[0])}">` : `<div class="item-img" style="display:grid;place-items:center;color:#555">Aperçu</div>`;
        return `
        <div class="card">
          ${img}
          <h3 style="margin:12px 0 6px">${esc(it.title)}</h3>
          <div class="muted" style="min-height:48px">${esc(it.description).slice(0, 90)}${it.description.length > 90 ? "…" : ""}</div>
          <div class="price" style="margin:10px 0">${Number(it.price).toFixed(2)} €</div>
          <a class="btn" href="/item/${it.id}">Voir l'annonce</a>
        </div>`;
      })
      .join("");
    const body = `
      <h1>Bienvenue sur Cedelec Vente</h1>
      <div class="grid cards">${cards || `<div class="card">Aucune annonce pour l’instant.</div>`}</div>
    `;
    res.send(page("Cedelec Vente", body, req.session.user));
  });
});

app.get("/item/:id", (req, res) => {
  db.get(`SELECT * FROM items WHERE id=?`, [req.params.id], (err, it) => {
    if (err || !it) return res.status(404).send("Annonce introuvable");
    const imgs = JSON.parse(it.images_json || "[]").map(u => `<img src="${esc(u)}" class="item-img">`).join("");
    const body = `
      <a href="/" class="muted">← Retour</a>
      <div class="grid" style="grid-template-columns:1fr 1fr">
        <div class="card">${imgs || `<div class="card">Aucune photo</div>`}</div>
        <div class="card">
          <h1 style="margin-top:0">${esc(it.title)}</h1>
          <p>${esc(it.description)}</p>
          <p class="price">${Number(it.price).toFixed(2)} €</p>
          ${req.session.user ? `<a class="btn" href="/chat/${it.id}">💬 Contacter</a>` : `<a class="btn" href="/login?next=${encodeURIComponent("/item/" + it.id)}">Se connecter</a>`}
        </div>
      </div>`;
    res.send(page(it.title, body, req.session.user));
  });
});

// ---------- Auth ----------
app.get("/register", (req, res) => {
  const body = `
    <div class="card" style="max-width:520px;margin:0 auto">
      <h2>Créer un compte</h2>
      <form method="post">
        <label>Nom d'utilisateur</label><input name="username" required><br>
        <label>Mot de passe</label><input type="password" name="password" required><br>
        <div style="margin-top:12px"><button class="btn">Créer</button></div>
      </form>
      <p><a href="/login">Déjà un compte ? Se connecter</a></p>
    </div>`;
  res.send(page("Créer un compte", body, req.session.user));
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send("Champs requis");
  bcrypt.hash(password, 10).then((hash) => {
    db.run(
      `INSERT INTO users (username, password_hash) VALUES (?,?)`,
      [username.trim(), hash],
      (err) => {
        if (err) return res.send("Nom d'utilisateur indisponible");
        db.get(
          `SELECT id, username, role FROM users WHERE username=?`,
          [username.trim()],
          (e, row) => {
            req.session.user = row;
            res.redirect("/");
          }
        );
      }
    );
  });
});

app.get("/login", (req, res) => {
  const next = req.query.next || "/";
  const body = `
    <div class="card" style="max-width:520px;margin:0 auto">
      <h2>Connexion</h2>
      <form method="post">
        <input type="hidden" name="next" value="${esc(next)}">
        <label>Nom d'utilisateur</label><input name="username" required><br>
        <label>Mot de passe</label><input type="password" name="password" required><br>
        <div style="margin-top:12px"><button class="btn">Se connecter</button></div>
      </form>
      <p><a href="/register">Créer un compte</a> • <a href="/">Retour</a></p>
    </div>`;
  res.send(page("Connexion", body, req.session.user));
});

app.post("/login", (req, res) => {
  const { username, password, next } = req.body;
  db.get(`SELECT * FROM users WHERE username=?`, [username], async (err, user) => {
    if (err || !user) return res.send("Identifiants invalides");
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.send("Identifiants invalides");
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect(next || "/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---------- Admin (ajout + gestion annonces) ----------
app.get("/admin", requireAdmin, (req, res) => {
  const body = `
    <div class="grid" style="grid-template-columns:1fr 1fr">
      <div class="card">
        <h3>Ajouter une annonce</h3>
        <form method="post" action="/admin/items" enctype="multipart/form-data">
          <label>Titre</label><input name="title" required><br>
          <label>Description</label><textarea name="description" required></textarea><br>
          <label>Prix (€)</label><input type="number" step="0.01" name="price" required><br>
          <label>Photos</label><input type="file" name="images" multiple accept="image/*"><br>
          <div style="margin-top:12px"><button class="btn">Publier</button></div>
        </form>
      </div>
      <div class="card">
        <h3>Liens rapides</h3>
        <p><a class="btn secondary" href="/admin/items">Gérer les annonces</a></p>
        <p><a class="btn secondary" href="/admin/conversations">Conversations</a></p>
      </div>
    </div>`;
  res.send(page("Admin", body, req.session.user));
});

app.post("/admin/items", requireAdmin, upload.array("images", 6), (req, res) => {
  const { title, description, price } = req.body;
  const files = (req.files || []).map((f) => `/uploads/${f.filename}`);
  db.run(
    `INSERT INTO items (title, description, price, images_json) VALUES (?,?,?,?)`,
    [title, description, Number(price || 0), JSON.stringify(files)],
    (err) => {
      if (err) return res.status(500).send("Erreur DB");
      res.redirect("/admin/items");
    }
  );
});

app.get("/admin/items", requireAdmin, (req, res) => {
  db.all(`SELECT * FROM items ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).send("Erreur DB");
    const lis = (rows || []).map(it => {
      const first = (JSON.parse(it.images_json || "[]")[0] || "");
      return `<li style="margin:8px 0">ID ${it.id} — <b>${esc(it.title)}</b> — ${Number(it.price).toFixed(2)} €
        ${first ? `<img src="${esc(first)}" width="60" style="vertical-align:middle;border-radius:6px">` : ""}
        • <a href="/item/${it.id}" target="_blank">Voir</a></li>`;
    }).join("");
    const body = `<div class="card"><h1>Annonces</h1><ul>${lis || "<li>Aucune</li>"}</ul><a class="btn secondary" href="/admin">← Admin</a></div>`;
    res.send(page("Annonces", body, req.session.user));
  });
});

// ---------- Conversations / Chat ----------
app.get("/chat/:itemId", requireLogin, (req, res) => {
  const itemId = Number(req.params.itemId);
  // crée/retourne la conversation user<->item
  db.get(
    `SELECT id FROM conversations WHERE item_id=? AND user_id=?`,
    [itemId, req.session.user.id],
    (err, row) => {
      if (row) return renderChat(row.id);
      db.run(
        `INSERT INTO conversations (item_id, user_id) VALUES (?,?)`,
        [itemId, req.session.user.id],
        function () { return renderChat(this.lastID); }
      );
    }
  );

  function renderChat(convoId) {
    const body = `
      <div class="card">
        <h2>Discussion pour l'annonce #${itemId}</h2>
        <div id="messages" class="chat-box"></div>
        <div style="margin-top:10px">
          <input id="msg" placeholder="Votre message" />
          <button class="btn" onclick="sendMsg()">Envoyer</button>
        </div>
      </div>
      <script src="/socket.io/socket.io.js"></script>
      <script>
        const socket = io();
        const room = "convo_${convoId}";
        const me = ${req.session.user.id};
        socket.emit('join', { room });
        socket.on('message', m=>{
          const box=document.getElementById('messages');
          box.innerHTML += '<p><b>'+m.sender+':</b> '+m.body+'</p>';
          box.scrollTop = box.scrollHeight;
        });
        async function sendMsg(){
          const input=document.getElementById('msg');
          const body=input.value.trim(); if(!body) return;
          await fetch('/api/conversations/${convoId}/messages', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ body })
          });
          input.value='';
        }
      </script>
      <p><a class="btn secondary" href="/item/${itemId}">← Retour à l'annonce</a></p>
    `;
    res.send(page("Discussion", body, req.session.user));
  }
});

// Liste des conversations (admin)
app.get("/admin/conversations", requireAdmin, (req, res) => {
  const sql = `SELECT c.id, u.username, i.title AS item_title
               FROM conversations c
               JOIN users u ON u.id = c.user_id
               JOIN items i ON i.id = c.item_id
               ORDER BY c.id DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).send("Erreur DB");
    const lis = (rows || [])
      .map((r) => `<li>#${r.id} • ${esc(r.username)} → ${esc(r.item_title)} • <a href="/admin/conversations/${r.id}">Ouvrir</a></li>`)
      .join("");
    const body = `<div class="card"><h1>Conversations</h1><ul>${lis || "<li>Aucune</li>"}</ul><a class="btn secondary" href="/admin">← Admin</a></div>`;
    res.send(page("Conversations", body, req.session.user));
  });
});

// Vue d’une conversation (admin)
app.get("/admin/conversations/:id", requireAdmin, (req, res) => {
  const cid = Number(req.params.id);
  const body = `
    <div class="card">
      <h1>Discussion #${cid}</h1>
      <div id="messages" class="chat-box"></div>
      <div style="margin-top:10px">
        <input id="msg" placeholder="Votre message"><button class="btn" onclick="send()">Envoyer</button>
      </div>
    </div>
    <script src="/socket.io/socket.io.js"></script>
    <script>
      const cid=${cid};
      const s = io();
      s.emit('join', { room: "convo_"+cid });
      s.on('message', (m)=>{ const div=document.getElementById('messages'); div.innerHTML += '<p><b>'+m.sender+':</b> '+m.body+'</p>'; });
      async function send(){
        const body = document.getElementById('msg').value.trim();
        if(!body) return;
        document.getElementById('msg').value='';
        await fetch('/api/conversations/'+cid+'/messages', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ body }) });
      }
    </script>
    <p><a class="btn secondary" href="/admin/conversations">← Conversations</a></p>
  `;
  res.send(page("Discussion admin", body, req.session.user));
});

// API messages (commune user/admin)
app.get("/api/conversations/:id/messages", requireLogin, (req, res) => {
  const cid = Number(req.params.id);
  db.get(`SELECT * FROM conversations WHERE id=?`, [cid], (err, conv) => {
    if (err || !conv) return res.status(404).json({ error: "not_found" });
    if (req.session.user.role !== "admin" && conv.user_id !== req.session.user.id)
      return res.status(403).json({ error: "forbidden" });
    db.all(
      `SELECT m.*, (m.sender_id=?) AS mine FROM messages m WHERE conversation_id=? ORDER BY id ASC`,
      [req.session.user.id, cid],
      (e, rows) => {
        if (e) return res.status(500).json({ error: "db" });
        res.json(rows.map((r) => ({ id: r.id, body: r.body, mine: !!r.mine, created_at: r.created_at })));
      }
    );
  });
});

app.post("/api/conversations/:id/messages", requireLogin, (req, res) => {
  const cid = Number(req.params.id);
  const body = (req.body.body || "").trim();
  if (!body) return res.status(400).json({ error: "empty" });

  db.get(`SELECT * FROM conversations WHERE id=?`, [cid], (err, conv) => {
    if (err || !conv) return res.status(404).json({ error: "not_found" });
    if (req.session.user.role !== "admin" && conv.user_id !== req.session.user.id)
      return res.status(403).json({ error: "forbidden" });

    db.run(
      `INSERT INTO messages (conversation_id, sender_id, body) VALUES (?,?,?)`,
      [cid, req.session.user.id, body],
      function (e) {
        if (e) return res.status(500).json({ error: "db" });
        io.to("convo_" + cid).emit("message", { id: this.lastID, sender: req.session.user.username, body });
        res.json({ ok: true });
      }
    );
  });
});

// ---------- Socket.IO ----------
io.on("connection", (socket) => {
  socket.on("join", ({ room }) => {
    if (room) socket.join(room);
  });
});

// ---------- 404 ----------
app.use((req, res) => res.status(404).send("Page introuvable"));

// ---------- Start ----------
server.listen(PORT, () => console.log(`Serveur lancé sur ${PORT}`));
