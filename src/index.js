// SMART ATTENDANCE - Express server for Cloudflare Workers + D1 database
import { env } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";
import express from "express";

const app = express();
app.use(express.json({ limit: "1mb" }));

/* =====================================================
   SETTINGS
   ===================================================== */
const PBKDF2_ITERATIONS = 10000; // lower = faster on the free plan
const LOGIN_HOURS = 12; // how long a login stays valid
const SESSION_MINUTES = 60; // QR code works for 1 hour only
const DEFAULT_RADIUS_M = 100; // default allowed distance in meters

/* =====================================================
   SMALL HELPERS
   ===================================================== */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
const fail = (status, message) => {
  throw new HttpError(status, message);
};

const enc = new TextEncoder();
const dec = new TextDecoder();

// database shortcuts (always use ? so input is safe)
const q = {
  all: async (sql, ...p) => (await env.DB.prepare(sql).bind(...p).all()).results,
  one: async (sql, ...p) => await env.DB.prepare(sql).bind(...p).first(),
  run: async (sql, ...p) => await env.DB.prepare(sql).bind(...p).run(),
};

const clean = (v, max = 200) => String(v ?? "").trim().slice(0, max);
const toInt = (v) => {
  const n = Number(v);
  return Number.isInteger(n) ? n : null;
};
function isDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + "T00:00:00Z");
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
}
function generateDates(start, end, days) {
  const out = [];
  const stop = Date.parse(end + "T00:00:00Z");
  for (let t = Date.parse(start + "T00:00:00Z"); t <= stop; t += 86400000) {
    const d = new Date(t);
    if (days.includes(d.getUTCDay())) out.push(d.toISOString().slice(0, 10));
  }
  return out;
}
function distanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const rad = (x) => (x * Math.PI) / 180;
  const dLat = rad(lat2 - lat1);
  const dLon = rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
const pct = (a, b) => (b > 0 ? Math.round((a / b) * 1000) / 10 : 0);

/* =====================================================
   PASSWORDS + LOGIN TOKENS
   ===================================================== */
const toB64 = (buf) => {
  let s = "";
  for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
  return btoa(s);
};
const fromB64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
const toB64Url = (buf) => toB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64Url = (s) =>
  fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));

function safeEqual(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toB64(salt)}$${toB64(bits)}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const bits = await pbkdf2(password, fromB64(parts[2]), parseInt(parts[1], 10));
  return safeEqual(toB64(bits), parts[3]);
}
async function hmac(data) {
  if (!env.AUTH_SECRET) fail(500, "AUTH_SECRET is not set in Cloudflare (Settings > Variables and Secrets)");
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return toB64Url(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}
async function makeToken(role, id) {
  const payload = toB64Url(enc.encode(JSON.stringify({ r: role, i: id, e: Date.now() + LOGIN_HOURS * 3600000 })));
  return payload + "." + (await hmac(payload));
}
async function readToken(token) {
  const [payload, sig] = String(token || "").split(".");
  if (!payload || !sig) return null;
  if (!safeEqual(sig, await hmac(payload))) return null;
  try {
    const data = JSON.parse(dec.decode(fromB64Url(payload)));
    return data.e > Date.now() ? data : null;
  } catch {
    return null;
  }
}
function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
async function loginCookie(res, role, id) {
  const token = await makeToken(role, id);
  res.setHeader("Set-Cookie", `sa_token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${LOGIN_HOURS * 3600}`);
}
const auth = (...roles) => async (req, res, next) => {
  const data = await readToken(parseCookies(req.headers.cookie).sa_token);
  if (!data || !roles.includes(data.r)) return res.status(401).json({ error: "Please log in" });
  req.user = { role: data.r, id: data.i };
  next();
};

/* =====================================================
   PUBLIC ROUTES (no login needed)
   ===================================================== */
app.get("/api/universities", async (req, res) => {
  res.json(await q.all("SELECT id, name, motto FROM universities ORDER BY name"));
});

app.get("/api/universities/:id", async (req, res) => {
  const u = await q.one("SELECT id, name, motto, logo_data FROM universities WHERE id = ?", toInt(req.params.id));
  if (!u) fail(404, "University not found");
  res.json(u);
});

app.get("/api/courses", async (req, res) => {
  res.json(
    await q.all(
      "SELECT id, course_code, course_name FROM courses WHERE university_id = ? ORDER BY course_name",
      toInt(req.query.university_id)
    )
  );
});

app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "sa_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/me", auth("admin", "lecturer", "student"), async (req, res) => {
  const { role, id } = req.user;
  let row;
  if (role === "admin") row = await q.one("SELECT username AS name FROM admins WHERE id = ?", id);
  else if (role === "lecturer")
    row = await q.one(
      "SELECT l.full_name AS name, u.name AS university FROM lecturers l JOIN universities u ON u.id = l.university_id WHERE l.id = ?",
      id
    );
  else
    row = await q.one(
      `SELECT s.full_name AS name, s.reg_number, u.name AS university, c.course_name
       FROM students s JOIN universities u ON u.id = s.university_id
       LEFT JOIN courses c ON c.id = s.course_id WHERE s.id = ?`,
      id
    );
  if (!row) return res.status(401).json({ error: "Please log in" });
  res.json({ role, ...row });
});

/* ---------- student register + login ---------- */
app.post("/api/student/register", async (req, res) => {
  const b = req.body || {};
  const reg = clean(b.reg_number, 50).toUpperCase();
  const name = clean(b.full_name, 120);
  const email = clean(b.email, 120);
  const uni = toInt(b.university_id);
  const course = toInt(b.course_id);
  const password = String(b.password || "");
  if (!reg || !name) fail(400, "Registration number and full name are required");
  if (password.length < 6) fail(400, "Password must be at least 6 characters");
  const c = await q.one("SELECT id FROM courses WHERE id = ? AND university_id = ?", course, uni);
  if (!c) fail(400, "Please choose your university and your course");
  if (await q.one("SELECT id FROM students WHERE reg_number = ?", reg))
    fail(409, "This registration number is already registered. Please log in.");
  await q.run(
    "INSERT INTO students (reg_number, full_name, email, university_id, course_id, password_hash) VALUES (?, ?, ?, ?, ?, ?)",
    reg, name, email || null, uni, course, await hashPassword(password)
  );
  res.status(201).json({ ok: true });
});

app.post("/api/student/login", async (req, res) => {
  const reg = clean(req.body?.reg_number, 50).toUpperCase();
  const s = await q.one("SELECT id, password_hash FROM students WHERE reg_number = ?", reg);
  if (!s || !(await verifyPassword(String(req.body?.password || ""), s.password_hash)))
    fail(401, "Wrong registration number or password");
  await loginCookie(res, "student", s.id);
  res.json({ ok: true });
});

/* ---------- lecturer login ---------- */
app.post("/api/lecturer/login", async (req, res) => {
  const lid = clean(req.body?.lecturer_id, 50);
  const l = await q.one("SELECT id, password_hash FROM lecturers WHERE lecturer_id = ?", lid);
  if (!l || !(await verifyPassword(String(req.body?.password || ""), l.password_hash)))
    fail(401, "Wrong lecturer ID or password");
  await loginCookie(res, "lecturer", l.id);
  res.json({ ok: true });
});

/* ---------- admin setup + login ---------- */
app.get("/api/admin/status", async (req, res) => {
  const c = await q.one("SELECT COUNT(*) AS n FROM admins");
  res.json({ has_admin: c.n > 0 });
});

app.post("/api/admin/setup", async (req, res) => {
  const c = await q.one("SELECT COUNT(*) AS n FROM admins");
  if (c.n > 0) fail(403, "Admin already exists");
  if (!env.SETUP_CODE) fail(500, "SETUP_CODE is not set in Cloudflare (Settings > Variables and Secrets)");
  if (!safeEqual(String(req.body?.setup_code || ""), String(env.SETUP_CODE))) fail(403, "Wrong setup code");
  const username = clean(req.body?.username, 50);
  const password = String(req.body?.password || "");
  if (!username) fail(400, "Username is required");
  if (password.length < 8) fail(400, "Admin password must be at least 8 characters");
  await q.run("INSERT INTO admins (username, password_hash) VALUES (?, ?)", username, await hashPassword(password));
  res.status(201).json({ ok: true });
});

app.post("/api/admin/login", async (req, res) => {
  const a = await q.one("SELECT id, password_hash FROM admins WHERE username = ?", clean(req.body?.username, 50));
  if (!a || !(await verifyPassword(String(req.body?.password || ""), a.password_hash)))
    fail(401, "Wrong username or password");
  await loginCookie(res, "admin", a.id);
  res.json({ ok: true });
});

/* =====================================================
   ADMIN ROUTES
   ===================================================== */
const admin = auth("admin");

function checkLogo(logo) {
  if (!logo) return null;
  if (!/^data:image\/(png|jpeg|webp);base64,/.test(logo)) fail(400, "Logo must be a PNG, JPG or WEBP image");
  if (logo.length > 700000) fail(400, "Logo is too big. Use a smaller image.");
  return logo;
}

/* ---- universities ---- */
app.get("/api/admin/universities", admin, async (req, res) => {
  res.json(await q.all("SELECT id, name, motto, logo_data FROM universities ORDER BY name"));
});
app.post("/api/admin/universities", admin, async (req, res) => {
  const name = clean(req.body?.name, 150);
  if (!name) fail(400, "University name is required");
  await q.run(
    "INSERT INTO universities (name, motto, logo_data) VALUES (?, ?, ?)",
    name, clean(req.body?.motto, 255) || null, checkLogo(req.body?.logo_data)
  );
  res.status(201).json({ ok: true });
});
app.put("/api/admin/universities/:id", admin, async (req, res) => {
  const id = toInt(req.params.id);
  const old = await q.one("SELECT * FROM universities WHERE id = ?", id);
  if (!old) fail(404, "University not found");
  const name = clean(req.body?.name, 150) || old.name;
  const motto = req.body?.motto === undefined ? old.motto : clean(req.body.motto, 255) || null;
  const logo = req.body?.logo_data ? checkLogo(req.body.logo_data) : old.logo_data;
  await q.run("UPDATE universities SET name = ?, motto = ?, logo_data = ? WHERE id = ?", name, motto, logo, id);
  res.json({ ok: true });
});
app.delete("/api/admin/universities/:id", admin, async (req, res) => {
  await q.run("DELETE FROM universities WHERE id = ?", toInt(req.params.id));
  res.json({ ok: true });
});

/* ---- departments ---- */
app.get("/api/admin/departments", admin, async (req, res) => {
  res.json(await q.all("SELECT id, department_name FROM departments ORDER BY department_name"));
});
app.post("/api/admin/departments", admin, async (req, res) => {
  const name = clean(req.body?.department_name, 120);
  if (!name) fail(400, "Department name is required");
  await q.run("INSERT INTO departments (department_name) VALUES (?)", name);
  res.status(201).json({ ok: true });
});
app.delete("/api/admin/departments/:id", admin, async (req, res) => {
  await q.run("DELETE FROM departments WHERE id = ?", toInt(req.params.id));
  res.json({ ok: true });
});

/* ---- courses ---- */
app.get("/api/admin/courses", admin, async (req, res) => {
  res.json(
    await q.all(
      `SELECT c.id, c.course_code, c.course_name, c.university_id, u.name AS university, d.department_name
       FROM courses c JOIN universities u ON u.id = c.university_id
       LEFT JOIN departments d ON d.id = c.department_id
       ORDER BY u.name, c.course_name`
    )
  );
});
app.post("/api/admin/courses", admin, async (req, res) => {
  const code = clean(req.body?.course_code, 30);
  const name = clean(req.body?.course_name, 150);
  const uni = toInt(req.body?.university_id);
  const dep = toInt(req.body?.department_id);
  if (!code || !name || !uni) fail(400, "Course code, course name and university are required");
  await q.run(
    "INSERT INTO courses (course_code, course_name, university_id, department_id) VALUES (?, ?, ?, ?)",
    code, name, uni, dep
  );
  res.status(201).json({ ok: true });
});
app.delete("/api/admin/courses/:id", admin, async (req, res) => {
  await q.run("DELETE FROM courses WHERE id = ?", toInt(req.params.id));
  res.json({ ok: true });
});

/* ---- lecturers ---- */
app.get("/api/admin/lecturers", admin, async (req, res) => {
  res.json(
    await q.all(
      `SELECT l.id, l.lecturer_id, l.full_name, l.email, u.name AS university, d.department_name,
        (SELECT group_concat(c.course_code, ', ') FROM lecturer_courses lc
          JOIN courses c ON c.id = lc.course_id WHERE lc.lecturer_id = l.id) AS courses
       FROM lecturers l JOIN universities u ON u.id = l.university_id
       LEFT JOIN departments d ON d.id = l.department_id
       ORDER BY l.full_name`
    )
  );
});
app.post("/api/admin/lecturers", admin, async (req, res) => {
  const b = req.body || {};
  const lid = clean(b.lecturer_id, 50);
  const name = clean(b.full_name, 120);
  const uni = toInt(b.university_id);
  const password = String(b.password || "");
  if (!lid || !name || !uni) fail(400, "Lecturer ID, full name and university are required");
  if (password.length < 6) fail(400, "Password must be at least 6 characters");
  await q.run(
    "INSERT INTO lecturers (lecturer_id, full_name, email, university_id, department_id, password_hash) VALUES (?, ?, ?, ?, ?, ?)",
    lid, name, clean(b.email, 120) || null, uni, toInt(b.department_id), await hashPassword(password)
  );
  res.status(201).json({ ok: true });
});
app.delete("/api/admin/lecturers/:id", admin, async (req, res) => {
  await q.run("DELETE FROM lecturers WHERE id = ?", toInt(req.params.id));
  res.json({ ok: true });
});
app.get("/api/admin/lecturers/:id/courses", admin, async (req, res) => {
  const id = toInt(req.params.id);
  const l = await q.one("SELECT university_id FROM lecturers WHERE id = ?", id);
  if (!l) fail(404, "Lecturer not found");
  const available = await q.all(
    "SELECT id, course_code, course_name FROM courses WHERE university_id = ? ORDER BY course_name",
    l.university_id
  );
  const assigned = (await q.all("SELECT course_id FROM lecturer_courses WHERE lecturer_id = ?", id)).map((r) => r.course_id);
  res.json({ available, assigned });
});
app.put("/api/admin/lecturers/:id/courses", admin, async (req, res) => {
  const id = toInt(req.params.id);
  const l = await q.one("SELECT university_id FROM lecturers WHERE id = ?", id);
  if (!l) fail(404, "Lecturer not found");
  const allowed = new Set((await q.all("SELECT id FROM courses WHERE university_id = ?", l.university_id)).map((r) => r.id));
  const ids = [...new Set((req.body?.course_ids || []).map(toInt).filter((x) => x && allowed.has(x)))];
  await q.run("DELETE FROM lecturer_courses WHERE lecturer_id = ?", id);
  if (ids.length) {
    // ids are checked numbers, so it is safe to write them in the SQL text
    await q.run("INSERT INTO lecturer_courses (lecturer_id, course_id) VALUES " + ids.map((c) => `(${id}, ${c})`).join(", "));
  }
  res.json({ ok: true });
});

/* ---- students ---- */
app.get("/api/admin/students", admin, async (req, res) => {
  res.json(
    await q.all(
      `SELECT s.id, s.reg_number, s.full_name, s.email, u.name AS university, c.course_name
       FROM students s JOIN universities u ON u.id = s.university_id
       LEFT JOIN courses c ON c.id = s.course_id
       ORDER BY s.full_name`
    )
  );
});
app.delete("/api/admin/students/:id", admin, async (req, res) => {
  await q.run("DELETE FROM students WHERE id = ?", toInt(req.params.id));
  res.json({ ok: true });
});

/* ---- reset password (student or lecturer) ---- */
app.post("/api/admin/reset-password", admin, async (req, res) => {
  const table = req.body?.type === "lecturer" ? "lecturers" : "students";
  const password = String(req.body?.password || "");
  if (password.length < 6) fail(400, "Password must be at least 6 characters");
  await q.run(`UPDATE ${table} SET password_hash = ? WHERE id = ?`, await hashPassword(password), toInt(req.body?.id));
  res.json({ ok: true });
});

/* =====================================================
   LECTURER ROUTES
   ===================================================== */
const lecturer = auth("lecturer");

app.get("/api/lecturer/courses", lecturer, async (req, res) => {
  res.json(
    await q.all(
      `SELECT c.id, c.course_code, c.course_name FROM lecturer_courses lc
       JOIN courses c ON c.id = lc.course_id WHERE lc.lecturer_id = ? ORDER BY c.course_name`,
      req.user.id
    )
  );
});

app.get("/api/lecturer/modules", lecturer, async (req, res) => {
  res.json(
    await q.all(
      `SELECT m.id, m.module_name, m.start_date, m.end_date, c.course_code, c.course_name,
        (SELECT COUNT(*) FROM module_dates d WHERE d.module_id = m.id) AS lectures,
        (SELECT COUNT(*) FROM attendance_sessions s WHERE s.module_id = m.id) AS held
       FROM modules m JOIN courses c ON c.id = m.course_id
       WHERE m.lecturer_id = ? ORDER BY m.start_date DESC`,
      req.user.id
    )
  );
});

app.post("/api/lecturer/modules", lecturer, async (req, res) => {
  const b = req.body || {};
  const course = toInt(b.course_id);
  const name = clean(b.module_name, 150);
  const start = clean(b.start_date, 10);
  const end = clean(b.end_date, 10);
  const days = (Array.isArray(b.days) ? b.days : []).map(toInt).filter((d) => d !== null && d >= 0 && d <= 6);
  if (!name) fail(400, "Module name is required");
  if (!isDate(start) || !isDate(end)) fail(400, "Please choose a valid start date and end date");
  if (end < start) fail(400, "End date must be after the start date");
  if (!days.length) fail(400, "Choose at least one lecture day");
  if (!(await q.one("SELECT 1 AS ok FROM lecturer_courses WHERE lecturer_id = ? AND course_id = ?", req.user.id, course)))
    fail(403, "This course is not assigned to you");
  const dates = generateDates(start, end, days);
  if (!dates.length) fail(400, "There is no lecture day between these dates");
  if (dates.length > 150) fail(400, "Too many lecture dates (maximum 150). Make the period shorter.");
  const r = await q.run(
    "INSERT INTO modules (course_id, lecturer_id, module_name, start_date, end_date) VALUES (?, ?, ?, ?, ?)",
    course, req.user.id, name, start, end
  );
  const moduleId = r.meta.last_row_id;
  try {
    // dates were made by the server (checked format), so it is safe in the SQL text
    await q.run(
      "INSERT INTO module_dates (module_id, lecture_date) VALUES " + dates.map((d) => `(${moduleId}, '${d}')`).join(", ")
    );
  } catch (e) {
    await q.run("DELETE FROM modules WHERE id = ?", moduleId);
    throw e;
  }
  res.status(201).json({ ok: true, id: moduleId, lectures: dates.length });
});

app.delete("/api/lecturer/modules/:id", lecturer, async (req, res) => {
  await q.run("DELETE FROM modules WHERE id = ? AND lecturer_id = ?", toInt(req.params.id), req.user.id);
  res.json({ ok: true });
});

app.get("/api/lecturer/modules/:id/dates", lecturer, async (req, res) => {
  const id = toInt(req.params.id);
  const m = await q.one(
    `SELECT m.id, m.module_name, c.course_code, c.course_name, c.id AS course_id, c.university_id
     FROM modules m JOIN courses c ON c.id = m.course_id WHERE m.id = ? AND m.lecturer_id = ?`,
    id, req.user.id
  );
  if (!m) fail(404, "Module not found");
  const dates = await q.all(
    `SELECT d.id, d.lecture_date, s.id AS session_id, s.expires_at,
      (SELECT COUNT(*) FROM attendance_records r WHERE r.session_id = s.id AND r.attendance_status = 'Present') AS present,
      (SELECT COUNT(*) FROM attendance_records r WHERE r.session_id = s.id) AS scanned
     FROM module_dates d LEFT JOIN attendance_sessions s ON s.module_date_id = d.id
     WHERE d.module_id = ? ORDER BY d.lecture_date`,
    id
  );
  const enrolled = (await q.one("SELECT COUNT(*) AS n FROM students WHERE course_id = ? AND university_id = ?", m.course_id, m.university_id)).n;
  res.json({ module: m, dates, enrolled, now: Date.now() });
});

/* ---- start an attendance session (QR + lecturer location) ---- */
app.post("/api/lecturer/sessions", lecturer, async (req, res) => {
  const b = req.body || {};
  const dateId = toInt(b.module_date_id);
  const lat = Number(b.latitude);
  const lng = Number(b.longitude);
  const acc = Number(b.accuracy);
  let radius = toInt(b.radius_m) ?? DEFAULT_RADIUS_M;
  radius = Math.min(500, Math.max(20, radius));
  const d = await q.one(
    `SELECT d.id, d.module_id FROM module_dates d JOIN modules m ON m.id = d.module_id
     WHERE d.id = ? AND m.lecturer_id = ?`,
    dateId, req.user.id
  );
  if (!d) fail(404, "Lecture date not found");
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180)
    fail(400, "Your location was not received. Turn on GPS and try again.");
  if (!Number.isFinite(acc) || acc > 100)
    fail(422, "Your GPS is not accurate enough" + (Number.isFinite(acc) ? ` (about ${Math.round(acc)} m)` : "") + ". Go to an open place and try again.");
  if (await q.one("SELECT id FROM attendance_sessions WHERE module_date_id = ?", dateId))
    fail(409, "Attendance was already started for this date");
  const qr = Array.from(crypto.getRandomValues(new Uint8Array(8)), (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
  const now = new Date();
  const r = await q.run(
    `INSERT INTO attendance_sessions (module_id, module_date_id, lecturer_id, qr_code, room, latitude, longitude, radius_m, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    d.module_id, dateId, req.user.id, qr, clean(b.room, 60) || null, lat, lng, radius,
    now.toISOString(), new Date(now.getTime() + SESSION_MINUTES * 60000).toISOString()
  );
  res.status(201).json({ ok: true, id: r.meta.last_row_id });
});

app.get("/api/lecturer/sessions/:id", lecturer, async (req, res) => {
  const id = toInt(req.params.id);
  const s = await q.one(
    `SELECT s.id, s.qr_code, s.room, s.radius_m, s.created_at, s.expires_at, d.lecture_date,
            m.module_name, m.course_id, c.university_id
     FROM attendance_sessions s
     JOIN module_dates d ON d.id = s.module_date_id
     JOIN modules m ON m.id = s.module_id
     JOIN courses c ON c.id = m.course_id
     WHERE s.id = ? AND s.lecturer_id = ?`,
    id, req.user.id
  );
  if (!s) fail(404, "Session not found");
  const records = await q.all(
    `SELECT st.full_name, st.reg_number, r.scan_time, r.attendance_status, r.gps_status, r.distance_m
     FROM attendance_records r JOIN students st ON st.id = r.student_id
     WHERE r.session_id = ? ORDER BY r.scan_time DESC`,
    id
  );
  const enrolled = (await q.one("SELECT COUNT(*) AS n FROM students WHERE course_id = ? AND university_id = ?", s.course_id, s.university_id)).n;
  res.json({ session: s, records, enrolled, now: Date.now() });
});

app.delete("/api/lecturer/sessions/:id", lecturer, async (req, res) => {
  await q.run("DELETE FROM attendance_sessions WHERE id = ? AND lecturer_id = ?", toInt(req.params.id), req.user.id);
  res.json({ ok: true });
});

/* ---- report data (the browser makes the PDF) ---- */
app.get("/api/lecturer/modules/:id/report", lecturer, async (req, res) => {
  const id = toInt(req.params.id);
  const m = await q.one(
    `SELECT m.id, m.module_name, m.start_date, m.end_date, c.course_code, c.course_name, c.university_id,
            u.name AS uni_name, u.motto, u.logo_data, l.full_name AS lecturer_name
     FROM modules m JOIN courses c ON c.id = m.course_id
     JOIN universities u ON u.id = c.university_id
     JOIN lecturers l ON l.id = m.lecturer_id
     WHERE m.id = ? AND m.lecturer_id = ?`,
    id, req.user.id
  );
  if (!m) fail(404, "Module not found");
  const dates = await q.all(
    `SELECT d.lecture_date, s.id AS session_id FROM module_dates d
     LEFT JOIN attendance_sessions s ON s.module_date_id = d.id
     WHERE d.module_id = ? ORDER BY d.lecture_date`,
    id
  );
  const students = await q.all(
    "SELECT id, reg_number, full_name FROM students WHERE course_id = (SELECT course_id FROM modules WHERE id = ?) AND university_id = ? ORDER BY full_name",
    id, m.university_id
  );
  const recs = await q.all(
    `SELECT r.session_id, r.student_id FROM attendance_records r
     JOIN attendance_sessions s ON s.id = r.session_id
     WHERE s.module_id = ? AND r.attendance_status = 'Present'`,
    id
  );
  const present = new Set(recs.map((r) => r.session_id + "-" + r.student_id));
  const held = dates.filter((d) => d.session_id);
  let totalPresent = 0;
  const studentRows = students.map((s) => {
    const marks = held.map((d) => (present.has(d.session_id + "-" + s.id) ? "P" : "A"));
    const p = marks.filter((x) => x === "P").length;
    totalPresent += p;
    return { reg_number: s.reg_number, full_name: s.full_name, marks, present: p, percent: pct(p, held.length) };
  });
  const dateRows = held.map((d, i) => {
    const p = studentRows.filter((s) => s.marks[i] === "P").length;
    return { date: d.lecture_date, present: p, percent: pct(p, students.length) };
  });
  res.json({
    university: { name: m.uni_name, motto: m.motto, logo_data: m.logo_data },
    module: { name: m.module_name, start_date: m.start_date, end_date: m.end_date },
    course: { code: m.course_code, name: m.course_name },
    lecturer: m.lecturer_name,
    planned: dates.length,
    held: held.length,
    total_students: students.length,
    dates: dateRows,
    students: studentRows,
    overall_percent: pct(totalPresent, students.length * held.length),
  });
});

/* =====================================================
   STUDENT ROUTES
   ===================================================== */
const student = auth("student");

app.post("/api/student/scan", student, async (req, res) => {
  const b = req.body || {};
  const code = clean(b.qr_code, 100).toUpperCase();
  const lat = Number(b.latitude);
  const lng = Number(b.longitude);
  const acc = Number(b.accuracy);

  const s = await q.one(
    `SELECT s.id, s.latitude, s.longitude, s.radius_m, s.expires_at, m.course_id, c.university_id
     FROM attendance_sessions s JOIN modules m ON m.id = s.module_id
     JOIN courses c ON c.id = m.course_id WHERE s.qr_code = ?`,
    code
  );
  if (!s) fail(404, "This QR code is not valid");
  const me = await q.one("SELECT id, course_id, university_id FROM students WHERE id = ?", req.user.id);
  if (!me) fail(401, "Please log in");
  if (me.university_id !== s.university_id || me.course_id !== s.course_id)
    fail(403, "This attendance is not for your course");
  if (Date.now() > Date.parse(s.expires_at)) fail(410, "This QR code has expired (it works for 1 hour only)");
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180)
    fail(400, "Your location was not received. Turn on GPS, allow location, and scan again.");
  const maxAcc = Math.min(150, Math.max(50, s.radius_m));
  if (!Number.isFinite(acc) || acc > maxAcc)
    fail(422, "Your GPS is not accurate enough" + (Number.isFinite(acc) ? ` (about ${Math.round(acc)} m)` : "") + ". Go near a window or outside, wait a few seconds and scan again.");
  if (await q.one("SELECT id FROM attendance_records WHERE session_id = ? AND student_id = ?", s.id, me.id))
    fail(409, "You already made attendance for this lecture");

  const dist = Math.round(distanceMeters(lat, lng, s.latitude, s.longitude));
  const near = dist <= s.radius_m;
  await q.run(
    `INSERT INTO attendance_records (session_id, student_id, scan_time, latitude, longitude, accuracy_m, distance_m, gps_status, attendance_status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    s.id, me.id, new Date().toISOString(), lat, lng, Math.round(acc), dist, near ? "Near" : "Far", near ? "Present" : "Absent"
  );
  res.json({ ok: true, status: near ? "Present" : "Absent", distance_m: dist, radius_m: s.radius_m });
});

app.get("/api/student/history", student, async (req, res) => {
  const records = await q.all(
    `SELECT r.scan_time, r.attendance_status, r.distance_m, d.lecture_date, m.module_name
     FROM attendance_records r
     JOIN attendance_sessions s ON s.id = r.session_id
     JOIN module_dates d ON d.id = s.module_date_id
     JOIN modules m ON m.id = s.module_id
     WHERE r.student_id = ? ORDER BY r.scan_time DESC LIMIT 200`,
    req.user.id
  );
  const modules = await q.all(
    `SELECT m.id, m.module_name,
      (SELECT COUNT(*) FROM attendance_sessions s WHERE s.module_id = m.id) AS held,
      (SELECT COUNT(*) FROM attendance_records r JOIN attendance_sessions s2 ON s2.id = r.session_id
        WHERE s2.module_id = m.id AND r.student_id = ? AND r.attendance_status = 'Present') AS present
     FROM modules m WHERE m.course_id = (SELECT course_id FROM students WHERE id = ?)
     ORDER BY m.module_name`,
    req.user.id, req.user.id
  );
  res.json({ records, modules: modules.filter((m) => m.held > 0).map((m) => ({ ...m, percent: pct(m.present, m.held) })) });
});

/* =====================================================
   ERRORS + START
   ===================================================== */
app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  const msg = String(err?.message || "");
  if (err?.type === "entity.parse.failed") return res.status(400).json({ error: "Bad request" });
  if (err?.type === "entity.too.large") return res.status(413).json({ error: "Data is too big" });
  if (msg.includes("UNIQUE constraint failed")) return res.status(409).json({ error: "This record already exists" });
  if (msg.includes("FOREIGN KEY constraint failed")) return res.status(409).json({ error: "This action is not allowed because of linked records" });
  console.error(err);
  res.status(500).json({ error: "Server error. Please try again." });
});

app.listen(3000);
export default httpServerHandler({ port: 3000 });
