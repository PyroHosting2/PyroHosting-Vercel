import "dotenv/config";
import express from "express";
import session from "express-session";
import nunjucks from "nunjucks";
import flash from "connect-flash";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { openDb, initDb } from "./db.js";
import { discordAuthUrl, exchangeCodeForToken, fetchDiscordUser, upsertUser, addTransaction } from "./auth.js";
import { ProxmoxManager } from "./proxmox.js";
import { generatePassword, requireLogin, nowIso, isAdmin } from "./utils.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "change_me";

// Paths (project root is one level above node_backend/)
const PROJECT_ROOT = path.resolve(__dirname, "..");
const TEMPLATES_DIR = path.join(PROJECT_ROOT, "templates");
const STATIC_DIR = path.join(PROJECT_ROOT, "static");

// DB
const DB_PATH = process.env.DB_PATH ? path.resolve(__dirname, process.env.DB_PATH) : path.join(PROJECT_ROOT, "data.db");
const db = openDb(DB_PATH);
initDb(db);

// Admins
let adminIds = [];
try {
  const p = path.join(PROJECT_ROOT, "admins.json");
  if (fs.existsSync(p)) {
    const raw = JSON.parse(fs.readFileSync(p, "utf-8"));
    if (Array.isArray(raw)) adminIds = raw.map(String);
  }
} catch {}

// Discord OAuth
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "";

// Proxmox
const proxmox = new ProxmoxManager({
  user: process.env.PROXMOX_USER || "root",
  password: process.env.PROXMOX_PASSWORD || "",
  hosts: {
    [process.env.PROXMOX_NODE_RYZEN || "ryzen01"]: process.env.PROXMOX_HOST_RYZEN || ""
  }
});

const RYZEN_NODE = process.env.PROXMOX_NODE_RYZEN || "ryzen01";
const RYZEN_GW = process.env.GW_RYZEN || "5.175.221.1";
const NETMASK = Number(process.env.NETMASK || 24);

const RYZEN_TEMPLATES = {
  "Ubuntu 22.04": 900,
  "Debian 13": 901,
  "Windows Server 2022": 902
};

// Prices and configs (mirrors app.py defaults; adjust as needed)
const SERVER_PRICES = {
  "Ryzen Starter": 4.99,
  "Ryzen Pro": 9.99,
  "Ryzen Ultra": 14.99
};

const SERVER_CONFIGS = {
  "Ryzen Starter": { cores: 2, memory: 2048, disk: 30 },
  "Ryzen Pro": { cores: 4, memory: 4096, disk: 50 },
  "Ryzen Ultra": { cores: 6, memory: 8192, disk: 80 }
};

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, sameSite: 'lax' } // set true behind HTTPS reverse proxy with proper settings
}));
app.use(flash());

app.locals.adminIds = adminIds;

// Static
app.use("/static", express.static(STATIC_DIR));

// Nunjucks
nunjucks.configure(TEMPLATES_DIR, {
  autoescape: true,
  express: app,
  noCache: true
});
app.locals.url_for = (name, opts = {}) => {
  if (name === "static") return `/static/${opts.filename || ""}`;
  if (name === "profile_data") return "/profile/data";
  return "/";
};

// Make session + flash available in templates similar to Flask
app.use((req, res, next) => {
  res.locals.session = req.session;
  res.locals.get_flashed_messages = () => {
    const msgs = req.flash("info");
    const errs = req.flash("error");
    return [...msgs, ...errs];
  };
  next();
});

// Helpers
function currentUser(req) {
  return req.session?.user || null;
}

function refreshBalanceIntoSession(req) {
  const user = currentUser(req);
  if (!user) return;
  const row = db.prepare("SELECT balance, username FROM users WHERE id = ?").get(String(user.id));
  if (row) {
    req.session.user.balance = row.balance;
    req.session.user.username = row.username;
  }
}

// Pages
app.get("/", (req, res) => res.render("index.html"));
app.get("/servers", (req, res) => res.render("servers.html"));
app.get("/features", (req, res) => res.render("features.html"));
app.get("/support", (req, res) => res.render("support.html"));
app.get("/privacy", (req, res) => res.render("privacy.html"));
app.get("/tos", (req, res) => res.render("tos.html"));

app.get("/login", (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) {
    return res.status(500).send("Discord OAuth ist nicht konfiguriert. Bitte .env setzen.");
  }
  const url = discordAuthUrl({ clientId: DISCORD_CLIENT_ID, redirectUri: DISCORD_REDIRECT_URI });
  res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.redirect("/login");

    const tok = await exchangeCodeForToken({
      code,
      clientId: DISCORD_CLIENT_ID,
      clientSecret: DISCORD_CLIENT_SECRET,
      redirectUri: DISCORD_REDIRECT_URI
    });

    if (!tok?.access_token) {
      req.flash("error", "Discord Login fehlgeschlagen.");
      return res.redirect("/login");
    }
    const user = await fetchDiscordUser(tok.access_token);
    if (!user?.id) {
      req.flash("error", "Discord User konnte nicht geladen werden.");
      return res.redirect("/login");
    }

    upsertUser(db, { id: user.id, username: user.username });

    // Put user in session (like Flask)
    const row = db.prepare("SELECT balance FROM users WHERE id = ?").get(String(user.id));
    req.session.user = {
      id: String(user.id),
      username: user.username,
      balance: row?.balance ?? 10.0
    };

    res.redirect("/dashboard");
  } catch (e) {
    req.flash("error", `Auth Fehler: ${e?.message || String(e)}`);
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/dashboard", requireLogin, (req, res) => res.redirect("/dashboard/home"));
app.get("/dashboard/:tab", requireLogin, (req, res) => res.redirect(`/dashboard/${req.params.tab}/`));
app.get("/dashboard/:tab/:sub", requireLogin, (req, res) => {
  refreshBalanceIntoSession(req);
  const tab = req.params.tab || "home";
  const sub = req.params.sub || null;
  const user = currentUser(req);
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ?").all(String(user.id));
  res.render("dashboard.html", { tab, sub, user, servers, is_admin: isAdmin(req) });
});

app.get("/balance", requireLogin, (req, res) => {
  refreshBalanceIntoSession(req);
  const user = currentUser(req);
  const tx = db.prepare("SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 200").all(String(user.id));
  res.render("balance.html", { user, transactions: tx });
});

app.get("/profile", requireLogin, (req, res) => {
  refreshBalanceIntoSession(req);
  const user = currentUser(req);
  const data = db.prepare("SELECT * FROM user_data WHERE user_id = ?").get(String(user.id));
  res.render("profile.html", { user, data });
});

app.route = (path) => path; // shim for template expectations (not used)

// profile data page (GET shows form, POST saves)
app.get("/profile/data", requireLogin, (req, res) => {
  const user = currentUser(req);
  const data = db.prepare("SELECT * FROM user_data WHERE user_id = ?").get(String(user.id));
  res.render("profile_data.html", { user, data });
});

app.post("/profile/data", requireLogin, (req, res) => {
  const user = currentUser(req);
  const b = req.body || {};
  db.prepare(`
    INSERT INTO user_data (user_id, firstname, lastname, company, vat, street, houseno, zip, city, country, phone)
    VALUES (@user_id, @firstname, @lastname, @company, @vat, @street, @houseno, @zip, @city, @country, @phone)
    ON CONFLICT(user_id) DO UPDATE SET
      firstname=excluded.firstname,
      lastname=excluded.lastname,
      company=excluded.company,
      vat=excluded.vat,
      street=excluded.street,
      houseno=excluded.houseno,
      zip=excluded.zip,
      city=excluded.city,
      country=excluded.country,
      phone=excluded.phone
  `).run({
    user_id: String(user.id),
    firstname: b.firstname || "",
    lastname: b.lastname || "",
    company: b.company || "",
    vat: b.vat || "",
    street: b.street || "",
    houseno: b.houseno || "",
    zip: b.zip || "",
    city: b.city || "",
    country: b.country || "",
    phone: b.phone || ""
  });
  req.flash("info", "Daten gespeichert.");
  res.redirect("/profile");
});

// Domains and Free server pages (render-only; purchase/claim endpoints below)
app.get("/domains", requireLogin, (req, res) => res.render("domains.html", { user: currentUser(req) }));
app.post("/domains", requireLogin, (req, res) => res.render("domains.html", { user: currentUser(req) }));
app.get("/free-server", requireLogin, (req, res) => res.render("free_server.html", { user: currentUser(req) }));

// Server manage
app.get("/server/:server_id", requireLogin, (req, res) => {
  const user = currentUser(req);
  const sid = String(req.params.server_id);
  const server = db.prepare("SELECT * FROM servers WHERE id = ? AND user_id = ?").get(sid, String(user.id));
  if (!server) return res.status(404).render("404.html");
  res.render("manage_server.html", { user, server });
});

app.get("/server/:server_id/vnc", requireLogin, (req, res) => {
  // This project originally used Proxmox noVNC. Implementing a full noVNC proxy in pure Node is out-of-scope here,
  // so we keep the page and show a placeholder. You can extend proxmox.js to create a VNC ticket & websocket.
  const user = currentUser(req);
  const sid = String(req.params.server_id);
  const server = db.prepare("SELECT * FROM servers WHERE id = ? AND user_id = ?").get(sid, String(user.id));
  if (!server) return res.status(404).render("404.html");
  res.render("console.html", { user, server, vnc_unavailable: true });
});

// JSON endpoints for provisioning/status/actions

app.get("/server/:server_id/provision_status", requireLogin, (req, res) => {
  const user = currentUser(req);
  const sid = String(req.params.server_id);
  const row = db.prepare("SELECT provisioning_status, status FROM servers WHERE id = ? AND user_id = ?").get(sid, String(user.id));
  if (!row) return res.json({ success: false, message: "Nicht gefunden" });
  res.json({ success: true, provisioning_status: row.provisioning_status, status: row.status });
});

async function ensureProxmoxReady() {
  if (!process.env.PROXMOX_HOST_RYZEN || !process.env.PROXMOX_PASSWORD) {
    proxmox.lastError = "Proxmox ist nicht konfiguriert (.env)";
    return false;
  }
  return true;
}

async function allocateFreeIp() {
  const row = db.prepare("SELECT ip FROM ips WHERE used = 0 AND ip LIKE '5.175.221.%' LIMIT 1").get();
  if (!row) return null;
  db.prepare("UPDATE ips SET used = 1 WHERE ip = ?").run(row.ip);
  return row.ip;
}

function deductBalance(userId, amount, description) {
  db.prepare("UPDATE users SET balance = balance - ? WHERE id = ?").run(amount, String(userId));
  addTransaction(db, { userId, amount: -amount, description, type: "neg" });
}

function markServerStatus(vmid, status, provisioning) {
  db.prepare("UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?").run(status, provisioning, String(vmid));
}

async function provisionVmInBackground({ vmid, userId, tier, osName, ip, price }) {
  try {
    markServerStatus(vmid, "Provisioning", "cloning");

    const cfg = SERVER_CONFIGS[tier] || SERVER_CONFIGS["Ryzen Starter"];
    const template = RYZEN_TEMPLATES[osName] || RYZEN_TEMPLATES["Ubuntu 22.04"];
    const name = `pyro-${userId}-${vmid}`;

    const okClone = await proxmox.cloneVm({ templateVmid: template, newVmid: vmid, name, node: RYZEN_NODE });
    if (!okClone) {
      markServerStatus(vmid, "Error", "failed");
      return;
    }

    // Password
    const password = generatePassword();
    db.prepare("UPDATE servers SET password = ?, os = ?, name = ?, ip = ?, cpu_series = ?, created_at = ? WHERE id = ?")
      .run(password, osName, name, ip, "Ryzen", nowIso(), String(vmid));

    markServerStatus(vmid, "Provisioning", "configuring");

    const ciUser = osName.includes("Windows") ? "Administrator" : "root";
    const okCi = await proxmox.configureCloudinit({ vmid, node: RYZEN_NODE, ip, gw: RYZEN_GW, netmask: NETMASK, username: ciUser, password });
    if (!okCi) {
      markServerStatus(vmid, "Error", "failed");
      return;
    }

    await proxmox.updateVmResources({ vmid, node: RYZEN_NODE, cores: cfg.cores, memoryMb: cfg.memory });
    await proxmox.resizeDisk({ vmid, node: RYZEN_NODE, sizeGb: cfg.disk });

    markServerStatus(vmid, "Provisioning", "starting");
    const okStart = await proxmox.startVm({ vmid, node: RYZEN_NODE });
    if (!okStart) {
      markServerStatus(vmid, "Error", "failed");
      return;
    }

    markServerStatus(vmid, "Running", "complete");
  } catch (e) {
    markServerStatus(vmid, "Error", "failed");
  }
}

// Buy server
app.post("/buy_server", requireLogin, async (req, res) => {
  try {
    const user = currentUser(req);
    const { tier, os } = req.body || req.json || {};
    const osName = os || "Ubuntu 22.04";
    const price = SERVER_PRICES[tier];
    if (!price) return res.json({ success: false, message: "Ungültiges Paket" });

    const row = db.prepare("SELECT balance FROM users WHERE id = ?").get(String(user.id));
    if (!row || row.balance < price) return res.json({ success: false, message: "Nicht genügend Guthaben!" });

    if (!(await ensureProxmoxReady())) return res.json({ success: false, message: proxmox.lastError });

    const ip = allocateFreeIp();
    if (!ip) return res.json({ success: false, message: "Keine freien IPs verfügbar!" });

    const vmid = await proxmox.getNextVmid({ node: RYZEN_NODE });
    if (!vmid) return res.json({ success: false, message: `Proxmox API Fehler: ${proxmox.lastError}` });

    // Remove any orphaned record
    const existing = db.prepare("SELECT id, ip FROM servers WHERE id = ?").get(String(vmid));
    if (existing) {
      if (existing.ip) db.prepare("UPDATE ips SET used = 0 WHERE ip = ?").run(existing.ip);
      db.prepare("DELETE FROM servers WHERE id = ?").run(String(vmid));
      db.prepare("DELETE FROM server_additional_ips WHERE server_id = ?").run(String(vmid));
    }

    deductBalance(user.id, price, `Kauf: ${tier} Server`);

    db.prepare(`
      INSERT INTO servers (id, user_id, name, os, ip, status, resources, price, expiry, created_at, password, provisioning_status, cpu_series, type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      String(vmid), String(user.id), `VM-${vmid}`, osName, ip, "Provisioning",
      JSON.stringify(SERVER_CONFIGS[tier] || SERVER_CONFIGS["Ryzen Starter"]),
      `${price.toFixed(2)}€`, "", nowIso(), "", "queued", "Ryzen", "qemu"
    );

    // Background provision (fire-and-forget)
    provisionVmInBackground({ vmid, userId: user.id, tier, osName, ip, price });

    res.json({ success: true, vmid });
  } catch (e) {
    res.json({ success: false, message: e?.message || String(e) });
  }
});

// Custom buy endpoint stub (kept for compatibility)
app.post("/buy_custom_server", requireLogin, async (req, res) => {
  res.json({ success: false, message: "Custom Server Kauf ist in der Node-Version noch nicht implementiert." });
});

// Server actions
async function userServer(req) {
  const user = currentUser(req);
  const sid = String(req.params.server_id);
  return db.prepare("SELECT * FROM servers WHERE id = ? AND user_id = ?").get(sid, String(user.id));
}

app.post("/server/:server_id/start", requireLogin, async (req, res) => {
  const s = await userServer(req);
  if (!s) return res.json({ success: false, message: "Nicht gefunden" });
  if (!(await ensureProxmoxReady())) return res.json({ success: false, message: proxmox.lastError });
  const ok = await proxmox.startVm({ vmid: s.id, node: RYZEN_NODE });
  if (!ok) return res.json({ success: false, message: proxmox.lastError });
  db.prepare("UPDATE servers SET status = ? WHERE id = ?").run("Running", String(s.id));
  res.json({ success: true });
});

app.post("/server/:server_id/stop", requireLogin, async (req, res) => {
  const s = await userServer(req);
  if (!s) return res.json({ success: false, message: "Nicht gefunden" });
  if (!(await ensureProxmoxReady())) return res.json({ success: false, message: proxmox.lastError });
  const ok = await proxmox.stopVm({ vmid: s.id, node: RYZEN_NODE });
  if (!ok) return res.json({ success: false, message: proxmox.lastError });
  db.prepare("UPDATE servers SET status = ? WHERE id = ?").run("Stopped", String(s.id));
  res.json({ success: true });
});

app.post("/server/:server_id/restart", requireLogin, async (req, res) => {
  const s = await userServer(req);
  if (!s) return res.json({ success: false, message: "Nicht gefunden" });
  if (!(await ensureProxmoxReady())) return res.json({ success: false, message: proxmox.lastError });
  const ok = await proxmox.rebootVm({ vmid: s.id, node: RYZEN_NODE });
  if (!ok) return res.json({ success: false, message: proxmox.lastError });
  res.json({ success: true });
});

app.post("/server/:server_id/pw-reset", requireLogin, async (req, res) => {
  const s = await userServer(req);
  if (!s) return res.json({ success: false, message: "Nicht gefunden" });
  const password = generatePassword();
  db.prepare("UPDATE servers SET password = ? WHERE id = ?").run(password, String(s.id));
  // Note: resetting actual OS password requires cloud-init or guest agent; not implemented here.
  res.json({ success: true, password });
});

app.post("/server/:server_id/reinstall", requireLogin, async (req, res) => {
  res.json({ success: false, message: "Reinstall ist in der Node-Version noch nicht implementiert." });
});

app.post("/server/:server_id/upgrade", requireLogin, async (req, res) => {
  res.json({ success: false, message: "Upgrade ist in der Node-Version noch nicht implementiert." });
});

// Admin endpoints (basic)
app.get("/admin/data", requireLogin, (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ success: false });
  const users = db.prepare("SELECT id, username, balance FROM users").all();
  const servers = db.prepare("SELECT * FROM servers").all();
  res.json({ success: true, users, servers });
});

app.post("/admin/user/:user_id/update_balance", requireLogin, (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ success: false });
  const userId = String(req.params.user_id);
  const amount = Number(req.body?.amount ?? 0);
  db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(amount, userId);
  addTransaction(db, { userId, amount, description: "Admin Balance Update", type: amount >= 0 ? "pos" : "neg" });
  res.json({ success: true });
});

app.post("/admin/server/:server_id/action", requireLogin, (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ success: false });
  res.json({ success: false, message: "Admin server action stub." });
});

// 404
app.use((req, res) => res.status(404).render("404.html"));

app.listen(PORT, () => {
  console.log(`PyroHosting Node backend läuft auf http://localhost:${PORT}`);
  console.log(`DB: ${DB_PATH}`);
});
