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
app.use(express.static(path.join(__dirname, "public")));
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "/tmp/data.sqlite";
const UPLOAD_DIR = process.env.UPLOAD_DIR || "/tmp/uploads";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-please";

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/uploads", express.static(UPLOAD_DIR));

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: path.dirname(DB_FILE) }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 },
  })
);

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

app.get("/", (req, res) => {
  const body = `
    <h1>Bienvenue sur Cedelec Vente</h1>
    <div class="card">
      <h3>Aucune annonce pour le moment.</h3>
      <p>Nous n'avons pas encore d'annonces disponibles, mais revenez bientôt pour découvrir nos objets en vente !</p>
    </div>
    <p><a class="btn" href="/login">Se connecter</a> | <a class="btn secondary" href="/register">Créer un compte</a></p>
  `;
  res.send(page("Accueil", body, req.session.user));
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

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

server.listen(PORT, () => console.log(`Serveur lancé sur ${PORT}`));


