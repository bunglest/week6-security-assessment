const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { db, initDB } = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ============================================================
// VULNERABILITY 1: Hardcoded JWT secret (A02 - Crypto Failure)
// ============================================================
const JWT_SECRET = 'secret123';

// ============================================================
// VULNERABILITY 5: No file type validation (A04 - Insecure Design)
// Allows uploading any file extension including .html, .php, .exe
// ============================================================
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
const upload = multer({ dest: 'uploads/' });
app.use('/uploads', express.static('uploads'));

// ============================================================
// VULNERABILITY 2: SQL Injection (A03 - Injection)
// Username and password are concatenated directly into the query.
// Payload: username = admin' OR '1'='1' --
// ============================================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, user) => {
    if (err) {
      // VULNERABILITY: Verbose error leaks raw SQL to client
      return res.status(500).json({ error: err.message, query });
    }
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // VULNERABILITY: No token expiry set
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username } });
  });
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  // VULNERABILITY: Password stored in plaintext
  db.run(
    `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`,
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, username });
    }
  );
});

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/api/tasks', auth, (req, res) => {
  db.all('SELECT * FROM tasks WHERE user_id = ?', [req.user.id], (err, tasks) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(tasks);
  });
});

// ============================================================
// VULNERABILITY 3: IDOR - Broken Access Control (A01)
// No ownership check — any authenticated user can read any task by ID.
// Logged in as alice (id=1), fetch GET /api/tasks/1 → gets bob's private task.
// ============================================================
app.get('/api/tasks/:id', auth, (req, res) => {
  db.get('SELECT * FROM tasks WHERE id = ?', [req.params.id], (err, task) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!task) return res.status(404).json({ error: 'Not found' });
    res.json(task); // No check that task.user_id === req.user.id
  });
});

// ============================================================
// VULNERABILITY 4: Stored XSS (A03 - Injection)
// Title/description are stored and later rendered via innerHTML.
// Payload: <img src=x onerror="alert(document.cookie)">
// ============================================================
app.post('/api/tasks', auth, (req, res) => {
  const { title, description } = req.body;
  db.run(
    'INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)',
    [req.user.id, title, description],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, title, description });
    }
  );
});

app.delete('/api/tasks/:id', auth, (req, res) => {
  // VULNERABILITY: IDOR on delete — no ownership check
  db.run('DELETE FROM tasks WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    message: 'File uploaded successfully',
    originalName: req.file.originalname,
    path: `/uploads/${req.file.filename}`,
  });
});

initDB(() => {
  app.listen(3000, () => {
    console.log('⚠️  Vulnerable app running on http://localhost:3000');
    console.log('Demo credentials: alice / password123  |  bob / hunter2');
  });
});
