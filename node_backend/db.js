import Database from "better-sqlite3";
import fs from "fs";
import path from "path";

export function openDb(dbPath) {
  // Ensure parent directory exists
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  return db;
}

export function initDb(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT,
      balance REAL DEFAULT 0.00
    );

    CREATE TABLE IF NOT EXISTS user_data (
      user_id TEXT PRIMARY KEY,
      firstname TEXT,
      lastname TEXT,
      company TEXT,
      vat TEXT,
      street TEXT,
      houseno TEXT,
      zip TEXT,
      city TEXT,
      country TEXT,
      phone TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      name TEXT,
      os TEXT,
      ip TEXT,
      status TEXT,
      resources TEXT,
      price TEXT,
      expiry TEXT,
      created_at TEXT,
      password TEXT,
      provisioning_status TEXT DEFAULT 'complete',
      cpu_series TEXT DEFAULT 'Intel',
      type TEXT DEFAULT 'qemu'
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      date TEXT,
      description TEXT,
      status TEXT,
      amount REAL,
      type TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS server_additional_ips (
      server_id TEXT,
      ip TEXT,
      net_id INTEGER,
      PRIMARY KEY (server_id, ip),
      FOREIGN KEY (server_id) REFERENCES servers (id),
      FOREIGN KEY (ip) REFERENCES ips (ip)
    );

    CREATE TABLE IF NOT EXISTS ips (
      ip TEXT PRIMARY KEY,
      used INTEGER DEFAULT 0
    );
  `);

  // Lightweight "migrations" mirroring app.py behavior (safe if columns already exist).
  const cols = db.prepare("PRAGMA table_info(servers)").all().map(r => r.name);
  const addCol = (name, ddl) => {
    if (!cols.includes(name)) {
      db.exec(`ALTER TABLE servers ADD COLUMN ${ddl}`);
    }
  };
  addCol("password", "password TEXT");
  addCol("created_at", "created_at TEXT");
  addCol("suspended", "suspended INTEGER DEFAULT 0");
  addCol("provisioning_status", "provisioning_status TEXT DEFAULT 'complete'");
  addCol("cpu_series", "cpu_series TEXT DEFAULT 'Intel'");
  addCol("type", "type TEXT DEFAULT 'qemu'");
}
