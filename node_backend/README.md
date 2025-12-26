# PyroHosting – Node.js Backend (Migration)

Dieses ZIP enthält dein ursprüngliches Projekt (Templates/Static) **plus** ein neues Node.js Backend unter `node_backend/`.

## Start (lokal)

```bash
cd node_backend
cp .env.example .env
# .env ausfüllen (Discord + Proxmox)
npm install
npm run start
```

Dann: http://localhost:3000

## Wichtige Hinweise / Unterschiede zur Python-Version

- **Templates** bleiben (Jinja-ähnlich) und werden mit **Nunjucks** gerendert.
- `url_for('static', ...)` funktioniert.
- Einige Features aus `app.py` sind als **Stub** umgesetzt (z.B. Reinstall/Upgrade/VNC Proxy).
- Proxmox Zugangsdaten werden **nur über .env** gelesen (keine Hardcodes im Code).
- Datenbank: SQLite `data.db` im Projekt-Root (wie vorher). Pfad via `DB_PATH` änderbar.

## Was wurde gemacht?

- Python Flask Backend ersetzt durch Express + Nunjucks.
- DB-Schema aus `app.py:init_db()` wurde nachgebaut (`node_backend/db.js`).
- Discord OAuth2 Login wurde portiert (`node_backend/auth.js` + Routen).
- Buy-Server + Provisioning (Clone + CloudInit + Resources + Start) wurde in Node nachgebaut (`node_backend/proxmox.js`).

Wenn du möchtest, kann ich dir als nächsten Schritt auch:
- VNC/noVNC Proxy sauber implementieren,
- die fehlenden Endpoints (Reinstall/Upgrade/Custom Buy) fertig portieren,
- oder die Proxmox-VM-Type Auswahl (qemu/lxc) ergänzen.
