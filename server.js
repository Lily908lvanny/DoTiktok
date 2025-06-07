const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const SECRET = 'super_secret_key';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// DB init
const db = new sqlite3.Database('./chat.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    username TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Auth routes
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' });
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], err => {
      if (err) return res.status(400).json({ error: 'Nom d’utilisateur déjà pris' });
      res.json({ success: true });
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user) return res.status(400).json({ error: 'Utilisateur introuvable' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(401).json({ error: 'Mot de passe incorrect' });
      const token = jwt.sign({ username }, SECRET);
      res.json({ token });
    });
  });
});

// Socket auth
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token requis'));
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return next(new Error('Token invalide'));
    socket.username = user.username;
    next();
  });
});

// Socket chat
io.on('connection', socket => {
  db.all('SELECT * FROM messages ORDER BY created_at ASC', [], (err, rows) => {
    socket.emit('history', rows);
  });

  socket.on('chat message', msg => {
    db.run('INSERT INTO messages (username, message) VALUES (?, ?)', [socket.username, msg]);
    io.emit('chat message', { username: socket.username, message: msg });
  });
});

// Supprimer les messages toutes les 24h
setInterval(() => {
  db.run('DELETE FROM messages');
  console.log('Messages supprimés');
}, 24 * 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Serveur lancé sur http://localhost:${PORT}`);
});