const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./taskdb.sqlite');

function initDB(cb) {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT,
      description TEXT
    )`);

    // Seed two demo users with plaintext passwords
    db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'alice', 'password123')`);
    db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (2, 'bob', 'hunter2')`);

    // Seed a private task owned by bob (id=2) — used to demo IDOR
    db.run(
      `INSERT OR IGNORE INTO tasks (id, user_id, title, description) VALUES (1, 2, 'Bob''s Private Task', 'Confidential: investor deck password is Seed2024!')`,
      cb
    );
  });
}

module.exports = { db, initDB };
