// server.js — Phase A
const express = require("express");
const http = require("http");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { z } = require("zod");
const sqlite3 = require("sqlite3").verbose();
const { Server } = require("socket.io");

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const PORT = process.env.PORT || 3000;

// --- App & HTTP ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

// --- Middlewares ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use("/auth", apiLimiter);
app.use("/history", apiLimiter);

// --- DB (SQLite) ---
const db = new sqlite3.Database(path.join(__dirname, "data.sqlite"));

db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON;`);

  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_seen_at INTEGER
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS rooms(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    is_private INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    FOREIGN KEY(created_by) REFERENCES users(id)
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS room_members(
    user_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY(user_id, room_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(room_id) REFERENCES rooms(id)
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER, -- DM nếu != NULL
    content TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'text',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    delivered_at INTEGER,
    seen_at INTEGER,
    FOREIGN KEY(room_id) REFERENCES rooms(id),
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
  );`);

  // tạo sẵn phòng "general" nếu chưa có
  db.run(
    `INSERT OR IGNORE INTO rooms(slug,name,is_private) VALUES('general','General',0);`
  );
});

// --- Helpers ---
function sign(user) {
  return jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "7d"
  });
}
function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

// --- Auth ---
const credSchema = z.object({
  username: z.string().min(3).max(24).regex(/^[a-zA-Z0-9_]+$/),
  password: z.string().min(6).max(100)
});

app.post("/auth/register", async (req, res) => {
  const parse = credSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid input" });
  const { username, password } = parse.data;
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users(username,password_hash) VALUES(?,?)`,
      [username, hash],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE"))
            return res.status(409).json({ error: "Username taken" });
          return res.status(500).json({ error: "DB error" });
        }
        const user = { id: this.lastID, username };
        return res.json({ token: sign(user), user });
      }
    );
  } catch {
    return res.status(500).json({ error: "Hash error" });
  }
});

app.post("/auth/login", (req, res) => {
  const parse = credSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid input" });
  const { username, password } = parse.data;
  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, row) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!row) return res.status(401).json({ error: "Wrong credentials" });
      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok) return res.status(401).json({ error: "Wrong credentials" });
      res.json({ token: sign(row), user: { id: row.id, username: row.username } });
    }
  );
});

// --- History (phân trang: before & limit) ---
app.get("/history/room/:slug", authMiddleware, (req, res) => {
  const { slug } = req.params;
  const before = Number(req.query.before) || nowSec() + 1; // < before
  const limit = Math.min(Number(req.query.limit) || 50, 100);

  db.get(`SELECT id FROM rooms WHERE slug = ?`, [slug], (err, room) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!room) return res.status(404).json({ error: "Room not found" });

    db.all(
      `SELECT m.id, m.content, m.created_at as ts, u.username as fromUser
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       WHERE m.room_id = ? AND m.created_at < ?
       ORDER BY m.created_at DESC
       LIMIT ?`,
      [room.id, before, limit],
      (err2, rows) => {
        if (err2) return res.status(500).json({ error: "DB error" });
        res.json({ messages: rows.reverse() });
      }
    );
  });
});

app.get("/history/dm/:username", authMiddleware, (req, res) => {
  const toUsername = req.params.username;
  const before = Number(req.query.before) || nowSec() + 1;
  const limit = Math.min(Number(req.query.limit) || 50, 100);

  db.get(`SELECT id FROM users WHERE username = ?`, [toUsername], (e, peer) => {
    if (e) return res.status(500).json({ error: "DB error" });
    if (!peer) return res.status(404).json({ error: "User not found" });

    const uid = req.user.uid;
    db.all(
      `SELECT m.id, m.content, m.created_at as ts,
              su.username as fromUser, ru.username as toUser
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       LEFT JOIN users ru ON ru.id = m.recipient_id
       WHERE m.room_id IS NULL
         AND ((m.sender_id = ? AND m.recipient_id = ?) OR
              (m.sender_id = ? AND m.recipient_id = ?))
         AND m.created_at < ?
       ORDER BY m.created_at DESC
       LIMIT ?`,
      [uid, peer.id, peer.id, uid, before, limit],
      (err2, rows) => {
        if (err2) return res.status(500).json({ error: "DB error" });
        res.json({ messages: rows.reverse() });
      }
    );
  });
});

// --- Presence state (in-memory) ---
const roomPresence = new Map(); // slug -> Map<socketId, username>

// --- Socket Rate limit (chống spam nhẹ) ---
const RATE_WINDOW_MS = 2000;
const RATE_MAX = 10;
const socketBuckets = new Map(); // socket.id -> [timestamps]

function canSend(id) {
  const now = Date.now();
  const arr = socketBuckets.get(id) || [];
  const alive = arr.filter(t => now - t < RATE_WINDOW_MS);
  if (alive.length >= RATE_MAX) {
    socketBuckets.set(id, alive);
    return false;
  }
  alive.push(now);
  socketBuckets.set(id, alive);
  return true;
}

// --- Socket.IO (namespace /chat) ---
const chat = io.of("/chat");

chat.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("Missing token"));
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = { id: payload.uid, username: payload.username };
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

chat.on("connection", (socket) => {
  const user = socket.user;

  socket.on("join_room", ({ slug }) => {
    if (!slug) return;
    socket.join(slug);

    if (!roomPresence.has(slug)) roomPresence.set(slug, new Map());
    roomPresence.get(slug).set(socket.id, user.username);

    // gửi presence cho phòng
    const users = Array.from(roomPresence.get(slug).values());
    chat.to(slug).emit("presence", { slug, users });

    // tiện lợi: gửi 50 tin gần nhất
    db.get(`SELECT id FROM rooms WHERE slug = ?`, [slug], (err, room) => {
      if (room) {
        db.all(
          `SELECT m.id, m.content, m.created_at as ts, u.username as fromUser
           FROM messages m
           JOIN users u ON u.id = m.sender_id
           WHERE m.room_id = ?
           ORDER BY m.created_at DESC
           LIMIT 50`,
          [room.id],
          (e2, rows) => {
            if (!e2) socket.emit("history", { slug, messages: rows.reverse() });
          }
        );
      }
    });
  });

  socket.on("leave_room", ({ slug }) => {
    socket.leave(slug);
    const mp = roomPresence.get(slug);
    if (mp) {
      mp.delete(socket.id);
      chat.to(slug).emit("presence", { slug, users: Array.from(mp.values()) });
    }
  });

  socket.on("typing", ({ slug }) => {
    socket.to(slug).emit("typing", { slug, from: user.username });
  });

  socket.on("send_room", ({ slug, content, tempId }) => {
    if (!canSend(socket.id)) return;
    const text = String(content || "").slice(0, 2000).trim();
    if (!slug || !text) return;

    db.get(`SELECT id FROM rooms WHERE slug = ?`, [slug], (err, room) => {
      if (err || !room) return;
      db.run(
        `INSERT INTO messages(room_id, sender_id, content, delivered_at)
         VALUES(?,?,?,strftime('%s','now'))`,
        [room.id, user.id, text],
        function (e) {
          if (e) return;
          const msg = {
            id: this.lastID,
            slug,
            from: user.username,
            content: text,
            ts: nowSec()
          };
          chat.to(slug).emit("room_message", msg);
          socket.emit("delivered", { id: msg.id, tempId });
        }
      );
    });
  });

  socket.on("send_dm", ({ toUsername, content, tempId }) => {
    if (!canSend(socket.id)) return;
    const text = String(content || "").slice(0, 2000).trim();
    if (!toUsername || !text) return;

    db.get(`SELECT id FROM users WHERE username = ?`, [toUsername], (e, peer) => {
      if (e || !peer) return;
      db.run(
        `INSERT INTO messages(room_id, sender_id, recipient_id, content, delivered_at)
         VALUES(NULL, ?, ?, ?, strftime('%s','now'))`,
        [user.id, peer.id, text],
        function (e2) {
          if (e2) return;
          const msg = {
            id: this.lastID,
            from: user.username,
            to: toUsername,
            content: text,
            ts: nowSec()
          };
          // emit cho chính sender
          socket.emit("dm_message", msg);
          // emit cho tất cả socket của peer (nếu đang online)
          for (const [id, s] of chat.sockets) {
            if (s.user?.username === toUsername) chat.to(id).emit("dm_message", msg);
          }
          socket.emit("delivered", { id: msg.id, tempId });
        }
      );
    });
  });

  socket.on("disconnect", () => {
    // cập nhật presence ở các phòng socket đang tham gia
    for (const slug of socket.rooms) {
      if (slug === socket.id) continue;
      const mp = roomPresence.get(slug);
      if (mp) {
        mp.delete(socket.id);
        chat.to(slug).emit("presence", { slug, users: Array.from(mp.values()) });
      }
    }
    db.run(`UPDATE users SET last_seen_at = ? WHERE id = ?`, [nowSec(), user.id]);
  });
});

// --- Start ---
server.listen(PORT, () => {
  console.log("Server listening at", PORT);
});
