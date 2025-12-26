import axios from "axios";
import { nowIso } from "./utils.js";

const DISCORD_API = "https://discord.com/api";

export function discordAuthUrl({ clientId, redirectUri, scope = "identify" }) {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope
  });
  return `${DISCORD_API}/oauth2/authorize?${params.toString()}`;
}

export async function exchangeCodeForToken({ code, clientId, clientSecret, redirectUri }) {
  const params = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    scope: "identify"
  });

  const resp = await axios.post(`${DISCORD_API}/oauth2/token`, params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    validateStatus: s => s >= 200 && s < 500
  });
  if (resp.status >= 300) return null;
  return resp.data;
}

export async function fetchDiscordUser(accessToken) {
  const resp = await axios.get(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    validateStatus: s => s >= 200 && s < 500
  });
  if (resp.status >= 300) return null;
  return resp.data;
}

export function upsertUser(db, { id, username }) {
  const existing = db.prepare("SELECT id FROM users WHERE id = ?").get(String(id));
  if (!existing) {
    db.prepare("INSERT INTO users (id, username, balance) VALUES (?, ?, ?)").run(String(id), username, 10.0);
  } else {
    db.prepare("UPDATE users SET username = ? WHERE id = ?").run(username, String(id));
  }
}

export function addTransaction(db, { userId, amount, description, status = "done", type }) {
  db.prepare(
    "INSERT INTO transactions (user_id, date, description, status, amount, type) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(String(userId), nowIso(), description, status, amount, type);
}
