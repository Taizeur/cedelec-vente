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

const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "/tmp/data.sqlite";
const UPLOAD_DIR = process.env.UPLOAD_DIR || "/tmp/uploads";

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// --- DB init ---
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

  // create default admin
  db.get("SELECT COUNT(*) AS c FROM users WHERE role='admin'", async (err, row) => {
    if (row.c === 0) {
      const hash = await bcrypt.hash("changeme", 10);
      db.run("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
        ["admin", hash, "admin"]);
      console.log(">>> Compte admin créé : admin / changeme");
    }
  });
});

// --- App init ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/uploads", express.static(UPLOAD_DIR));

app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: path.dirname(DB_FILE) }),
  secret: process.env.SESSION_SECRET || "secret",
  resave: false,
  saveUninitialized: false
}));

// --- Multer config ---
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
  }),
  limits: { fileSize: 6 * 1024 * 1024, files: 6 }
});

// --- Middleware auth ---
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).send("Connectez-vous d'abord");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Admin requis");
  next();
}

// --- Routes ---
app.get("/", (req, res) => {
  db.all("SELECT * FROM items ORDER BY created_at DESC", (err, rows) => {
    const html = `
    <h1>Cedelec Vente</h1>
    ${req.session.user ? `<p>Connecté en tant que ${req.session.user.username} (${req.session.user.role})</p>` : `<a href="/login">Se connecter</a>`}
    <ul>
      ${rows.map(it => {
        const imgs = JSON.parse(it.images_json || "[]");
        const img = imgs[0] ? `<img src="${imgs[0]}" width="120">` : "";
        return `<li>${img}<br>${it.title} - ${it.price}€ 
          <a href="/item/${it.id}">Voir</a></li>`;
      }).join("")}
    </ul>
    ${req.session.user?.role === "admin" ? `<a href="/admin">Admin</a>` : ""}
    `;
    res.send(html);
  });
});

app.get("/item/:id", (req, res) => {
  db.get("SELECT * FROM items WHERE id=?", [req.params.id], (err, it) => {
    if (!it) return res.status(404).send("Introuvable");
    const imgs = JSON.parse(it.images_json || "[]")
      .map(u => `<img src="${u}" width="300">`).join("");
    res.send(`
      <h1>${it.title}</h1>
      ${imgs}<p>${it.description}</p>
      <p>Prix: ${it.price} €</p>
      ${req.session.user ? `<a href="/chat/${it.id}">💬 Contacter le vendeur</a>` : `<a href="/login">Se connecter</a>`}
      <br><a href="/">Retour</a>
    `);
  });
});

// --- Auth ---
app.get("/login", (req, res) => {
  res.send(`<form method="post">
    <input name="username" placeholder="Nom"><br>
    <input type="password" name="password" placeholder="Mot de passe"><br>
    <button type="submit">Connexion</button>
  </form>`);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (!user) return res.send("Utilisateur introuvable");
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.send("Mot de passe incorrect");
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect("/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// --- Admin ---
app.get("/admin", requireAdmin, (req, res) => {
  res.send(`
    <h1>Admin</h1>
    <form method="post" action="/admin/items" enctype="multipart/form-data">
      <input name="title" placeholder="Titre"><br>
      <textarea name="description"></textarea><br>
      <input name="price" placeholder="Prix"><br>
      <input type="file" name="images" multiple><br>
      <button>Ajouter</button>
    </form>
    <a href="/">Retour</a>
  `);
});

app.post("/admin/items", requireAdmin, upload.array("images", 6), (req, res) => {
  const { title, description, price } = req.body;
  const files = req.files.map(f => "/uploads/" + f.filename);
  db.run("INSERT INTO items (title, description, price, images_json) VALUES (?,?,?,?)",
    [title, description, price, JSON.stringify(files)],
    () => res.redirect("/"));
});

// --- Chat ---
app.get("/chat/:itemId", requireLogin, (req, res) => {
  const itemId = req.params.itemId;
  res.send(`
    <h1>Discussion sur l'annonce #${itemId}</h1>
    <div id="messages"></div>
    <input id="msg"><button onclick="sendMsg()">Envoyer</button>
    <script src="/socket.io/socket.io.js"></script>
    <script>
      const socket = io();
      const itemId=${itemId}, userId=${req.session.user.id};
      socket.emit('join', {itemId, userId});
      socket.on('message', m=>{
        const div=document.getElementById('messages');
        div.innerHTML += '<p><b>'+m.sender+':</b> '+m.body+'</p>';
      });
      function sendMsg(){
        const body=document.getElementById('msg').value;
        socket.emit('message', {itemId, userId, body});
        document.getElementById('msg').value='';
      }
    </script>
    <a href="/">Retour</a>
  `);
});

// --- Socket.IO ---
io.on("connection", (socket) => {
  socket.on("join", ({ itemId, userId }) => {
    const room = `item-${itemId}`;
    socket.join(room);
    socket.on("message", (msg) => {
      db.run("INSERT INTO messages (conversation_id, sender_id, body) VALUES (?,?,?)",
        [itemId, userId, msg.body]);
      io.to(room).emit("message", { sender: userId, body: msg.body });
    });
  });
});

// --- Lancement ---
server.listen(PORT, () => {
  console.log("Serveur lancé sur " + PORT);
});
