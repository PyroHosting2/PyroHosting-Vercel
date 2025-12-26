export function nowIso() {
  return new Date().toISOString();
}

export function generatePassword(length = 18) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

export function requireLogin(req, res, next) {
  if (!req.session?.user) return res.redirect("/login");
  next();
}

export function isAdmin(req) {
  const admins = req.app.locals.adminIds || [];
  const uid = req.session?.user?.id;
  return uid && admins.includes(String(uid));
}
