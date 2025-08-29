// Cedelec Vente – server.js (version Render gratuit : stockage en /tmp)
// Stack : Express + SQLite + Sessions + Multer + Socket.IO

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

// ---------- Config (Render gratuit : /tmp) ----------
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "/tmp/data.sqlite";
const UPLOAD_DIR = process.env.UPLOAD_DIR || "/tmp/uploads";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";

// Assure la présence du dossier d’uploads
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ---------- Base de données SQLite ----------
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

  // Compte admin par défaut
  db.get(`SELECT COUNT(*) AS c FROM users WHERE role='admin'`, async (err, row) => {
    if (err) return console.error(err);
    if ((row?.c || 0) === 0) {
      const hash = await bcrypt.hash("changeme", 10);
      db.run(
        `INSERT INTO users (username, password_hash, role) VALUES (?,?,?)`,
        ["admin", hash, "admin"],
        (e) => {
          if (e) console.error(e);
          else console.log('>>> Compte admin créé : admin / "changeme"');
        }
      );
    }
  });
});

// ---------- App/Serveur/Socket ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/uploads", express.static(UPLOAD_DIR));

// Sessions (stockées en fichier dans le même dossier que la DB)
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: path.dirname(DB_FILE) }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }, // 7 jours
  })
);

// Multer (upload sur disque /tmp/uploads)
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
  if (!req.session.user) return res.status(401).send('Vous devez être connecté. <a href="/login">Se connecter</a>');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).send("Accès admin requis");
  next();
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- Routes publiques ----------
app.get("/", (req, res) => {
  db.all(`SELECT * FROM items WHERE status='available' ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).send("Erreur DB");
    const list = rows
      .map((it) => {
        const imgs = JSON.parse(it.images_json || "[]");
        const first = imgs[0] || "";
        return `<li style="margin:12px 0">
          ${first ? `<img src="${esc(first)}" style="height:60px;border-radius:8px;vertical-align:middle"> ` : ""}
          <strong>${esc(it.title)}</strong> — ${Number(it.price).toFixed(2)} €
          <a href="/item/${it.id}" style="margin-left:10px">Voir</a>
        </li>`;
      })
      .join("");
    res.send(`
      <h1>Cedelec Vente</h1>
      <p>${req.session.user ? `Connecté : <b>${esc(req.session.user.username)}</b> (${req.session.user.role}) | <a href="/logout">Déconnexion</a>` : `<a href="/login">Connexion</a> | <a href="/register">Créer un compte</a>`}</p>
      <ul>${list || "<li>Aucun article</li>"}</ul>
      ${req.session.user?.role === "admin" ? `<p><a href="/admin">Espace admin</a></p>` : ""}
    `);
  });
});

app.get("/item/:id", (req, res) => {
  db.get(`SELECT * FROM items WHERE id=?`, [req.params.id], (err, it) => {
    if (err || !it) return res.status(404).send("Article introuvable");
    const imgs = JSON.parse(it.images_json || "[]")
      .map((u) => `<img src="${esc(u)}" style="max-width:280px;border-radius:10px;margin:6px">`)
      .join("");
    res.send(`
      <h1>${esc(it.title)}</h1>
      <div>${imgs || "<em>Aucune photo</em>"}</div>
      <p><b>Prix :</b> ${Number(it.price).toFixed(2)} €</p>
      <p style="white-space:pre-wrap">${esc(it.description)}</p>
      ${req.session.user ? `<p><a href="/chat/${it.id}">💬 Contacter le vendeur</a></p>` : `<p><a href="/login">Se connecter pour discuter</a></p>`}
      <p><a href="/">← Retour</a></p>
    `);
  });
});

// ---------- Auth ----------
app.get("/register", (req, res) => {
  res.send(`
    <h2>Créer un compte</h2>
    <form method="post">
      <input name="username" placeholder="Nom d'utilisateur" required /><br>
      <input type="password" name="password" placeholder="Mot de passe" required /><br>
      <button>Créer</button>
    </form>
    <p><a href="/login">J'ai déjà un compte</a></p>
  `);
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send("Champs requis");
  bcrypt.hash(password, 10).then((hash) => {
    db.run(
      `INSERT INTO users (username, password_hash) VALUES (?,?)`,
      [username.trim(), hash],
      function (err) {
        if (err) return res.send("Nom d'utilisateur indisponible");
        req.session.user = { id: this.lastID, username: username.trim(), role: "user" };
        res.redirect("/");
      }
    );
  });
});

app.get("/login", (req, res) => {
  res.send(`
    <h2>Connexion</h2>
    <form method="post">
      <input name="username" placeholder="Nom d'utilisateur" required /><br>
      <input type="password" name="password" placeholder="Mot de passe" required /><br>
      <button>Se connecter</button>
    </form>
    <p><a href="/register">Créer un compte</a></p>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username=?`, [username], async (err, user) => {
    if (err || !user) return res.send("Utilisateur introuvable");
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.send("Mot de passe incorrect");
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect("/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---------- Admin ----------
app.get("/admin", requireAdmin, (req, res) => {
  res.send(`
    <h1>Admin</h1>
    <h3>Ajouter un article</h3>
    <form method="post" action="/admin/items" enctype="multipart/form-data">
      <input name="title" placeholder="Titre" required /><br>
      <textarea name="description" placeholder="Description" required></textarea><br>
      <input name="price" type="number" step="0.01" placeholder="Prix (€)" required /><br>
      <input type="file" name="images" multiple accept="image/*" /><br>
      <button>Publier</button>
    </form>
    <p><a href="/">← Retour</a></p>
  `);
});

app.post("/admin/items", requireAdmin, upload.array("images", 6), (req, res) => {
  const { title, description, price } = req.body;
  const files = (req.files || []).map((f) => `/uploads/${f.filename}`);
  db.run(
    `INSERT INTO items (title, description, price, images_json) VALUES (?,?,?,?)`,
    [title, description, Number(price || 0), JSON.stringify(files)],
    (err) => {
      if (err) return res.status(500).send("Erreur DB");
      res.redirect("/");
    }
  );
});

// ---------- Chat ----------
app.get("/chat/:itemId", requireLogin, (req, res) => {
  const itemId = Number(req.params.itemId);
  res.send(`
    <h1>Discussion sur l'annonce #${itemId}</h1>
    <div id="messages" style="border:1px solid #ccc;padding:8px;height:260px;overflow:auto;margin-bottom:8px"></div>
    <input id="msg" style="width:70%"><button onclick="sendMsg()">Envoyer</button>
    <script src="/socket.io/socket.io.js"></script>
    <script>
      const socket = io();
      const itemId = ${itemId};
      const me = ${req.session.user.id};
      socket.emit('join', { itemId, userId: me });
      socket.on('message', (m) => {
        const box = document.getElementById('messages');
        box.innerHTML += '<p><b>'+m.sender+':</b> '+m.body+'</p>';
        box.scrollTop = box.scrollHeight;
      });
      function sendMsg(){
        const input = document.getElementById('msg');
        const body = input.value.trim(); if(!body) return;
        socket.emit('message', { itemId, userId: me, body });
        input.value = '';
      }
    </script>
    <p><a href="/">← Retour</a></p>
  `);
});

// Socket.IO
io.on("connection", (socket) => {
  socket.on("join", ({ itemId, userId }) => {
    const room = `item-${itemId}`;
    socket.join(room);

    socket.on("message", (msg) => {
      // crée/conserve une conversation (simple : on utilise itemId comme conversation_id)
      db.run(
        `INSERT INTO messages (conversation_id, sender_id, body) VALUES (?,?,?)`,
        [itemId, userId, msg.body],
        (err) => {
          if (err) console.error(err);
        }
      );
      io.to(room).emit("message", { sender: userId, body: msg.body });
    });
  });
});

// ---------- Lancement ----------
server.listen(PORT, () => {
  console.log(`Serveur lancé sur ${PORT} (DB: ${DB_FILE}, UPLOADS: ${UPLOAD_DIR})`);
});

