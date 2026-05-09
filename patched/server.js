require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { db, initDB } = require('./db');

const app = express();

// FIX 5: Security headers via helmet (X-Frame-Options, CSP, HSTS, etc.)
// script-src 'self' blocks inline <script> tags; script-src-attr is relaxed
// to allow onclick/onsubmit attributes used in this demo UI.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      baseUri:       ["'self'"],
      fontSrc:       ["'self'", 'https:', 'data:'],
      formAction:    ["'self'"],
      frameAncestors:["'self'"],
      imgSrc:        ["'self'", 'data:'],
      objectSrc:     ["'none'"],
      scriptSrc:     ["'self'"],
      styleSrc:      ["'self'", 'https:', "'unsafe-inline'"],
      upgradeInsecureRequests: [],
      scriptSrcAttr: null, // null removes directive — allows onclick handlers in demo UI
    },
  },
}));
app.use(express.json());
app.use(express.static('public'));

// FIX 1: JWT secret loaded from environment variable, never hardcoded
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set');
  process.exit(1);
}

// FIX 2: Rate limiting on auth endpoints — blocks brute-force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts — please try again in 15 minutes' },
});

// FIX 5: File upload — whitelist by MIME type and extension only
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
const ALLOWED_EXTS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_TYPES.includes(file.mimetype) || !ALLOWED_EXTS.includes(ext)) {
      return cb(new Error('Only image files (jpg, png, gif) and PDFs are allowed'));
    }
    cb(null, true);
  },
});

// FIX 2: Parameterized query — no SQL injection possible
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Internal server error' }); // FIX: no raw error leaked
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // FIX 3: bcrypt comparison — passwords are hashed at rest
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    // FIX 1: Token has expiry (1 hour)
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, username: user.username } });
  });
});

app.post('/api/register', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  // FIX 3: Hash password before storing
  const hash = await bcrypt.hash(password, 12);
  db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash], function (err) {
    if (err) return res.status(400).json({ error: 'Username already taken' });
    res.json({ id: this.lastID, username });
  });
});

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.get('/api/tasks', auth, (req, res) => {
  db.all('SELECT * FROM tasks WHERE user_id = ?', [req.user.id], (err, tasks) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json(tasks);
  });
});

// FIX 4: Ownership check — user can only access their own tasks (fixes IDOR)
app.get('/api/tasks/:id', auth, (req, res) => {
  db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, task) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    if (!task) return res.status(404).json({ error: 'Task not found' }); // same message whether missing or unauthorized
    res.json(task);
  });
});

app.post('/api/tasks', auth, (req, res) => {
  const { title, description } = req.body;
  if (!title?.trim()) return res.status(400).json({ error: 'Title is required' });

  // Note: data is stored as-is (plain text). XSS prevention happens at render time
  // in the frontend by using textContent instead of innerHTML.
  db.run(
    'INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)',
    [req.user.id, title.trim(), (description || '').trim()],
    function (err) {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      res.json({ id: this.lastID, title, description });
    }
  );
});

// FIX 4: Ownership check on delete too
app.delete('/api/tasks/:id', auth, (req, res) => {
  db.run('DELETE FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Task not found' });
    res.json({ success: true });
  });
});

app.post('/api/upload', auth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ message: 'File uploaded successfully', originalName: req.file.originalname });
  });
});

initDB(() => {
  app.listen(3001, () => {
    console.log('Patched app running on http://localhost:3001');
    console.log('Register a new account to get started.');
  });
});
