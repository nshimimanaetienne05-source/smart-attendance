/* SMART ATTENDANCE - shared helpers for all pages */

async function api(path, method, body) {
  const opt = { method: method || "GET", headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, opt); } catch (e) { throw new Error("No internet connection. Please try again."); }
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) {
    const err = new Error((data && data.error) || "Something went wrong");
    err.status = res.status;
    throw err;
  }
  return data;
}

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function showMsg(id, text, type) {
  const el = $(id);
  if (!el) return;
  el.className = "msg " + (type || "error");
  el.textContent = text || "";
  el.style.display = text ? "block" : "none";
}

function fmtDate(d) { // 2026-10-14 -> 14 Oct 2026
  if (!d) return "";
  const dt = new Date(d + "T00:00:00Z");
  return dt.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" });
}
function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) : "";
}
function fmtDateTime(iso) {
  return iso ? new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
}

async function logout() {
  try { await api("/api/logout", "POST", {}); } catch (e) {}
  location.reload();
}

/* ---- GPS helper: keeps the best (most accurate) position ---- */
class LocationTracker {
  constructor(onUpdate) { this.best = null; this.watchId = null; this.error = null; this.onUpdate = onUpdate; }
  start() {
    this.stop();
    this.error = null;
    if (!navigator.geolocation) {
      this.error = "This browser has no GPS. Please use Chrome or Safari on your phone.";
      if (this.onUpdate) this.onUpdate(this);
      return;
    }
    this.watchId = navigator.geolocation.watchPosition(
      (p) => {
        const c = p.coords;
        if (!this.best || c.accuracy <= this.best.accuracy || Date.now() - this.best.time > 20000) {
          this.best = { latitude: c.latitude, longitude: c.longitude, accuracy: c.accuracy, time: Date.now() };
        }
        if (this.onUpdate) this.onUpdate(this);
      },
      (err) => {
        this.error = err.code === 1
          ? "Location is blocked. Allow location for this website in your browser settings, then try again."
          : "Cannot get your location. Turn on GPS (location) and try again.";
        if (this.onUpdate) this.onUpdate(this);
      },
      { enableHighAccuracy: true, maximumAge: 0, timeout: 20000 }
    );
  }
  stop() {
    if (this.watchId !== null) { navigator.geolocation.clearWatch(this.watchId); this.watchId = null; }
  }
  // wait until accuracy is good (or time is over) and return the best position
  async waitFor(goodAcc, maxMs) {
    const t0 = Date.now();
    while (Date.now() - t0 < maxMs) {
      if (this.best && this.best.accuracy <= goodAcc) break;
      if (this.error && !this.best) break;
      await new Promise((r) => setTimeout(r, 400));
    }
    return this.best;
  }
}

/* ---- make a small logo from an image file (saved as text in the database) ---- */
function fileToLogo(file, max) {
  max = max || 256;
  return new Promise((resolve, reject) => {
    if (!file || !file.type.startsWith("image/")) return reject(new Error("Please choose an image file"));
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      const s = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement("canvas");
      c.width = Math.max(1, Math.round(img.width * s));
      c.height = Math.max(1, Math.round(img.height * s));
      c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(url);
      resolve(c.toDataURL("image/png"));
    };
    img.onerror = () => reject(new Error("Cannot read this image"));
    img.src = url;
  });
}
