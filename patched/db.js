const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./taskdb.sqlite');

function initDB(cb) {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT,
      description TEXT
    )`, cb);
  });
}

module.exports = { db, initDB };
