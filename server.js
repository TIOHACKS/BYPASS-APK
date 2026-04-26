const express = require("express");
const axios   = require("axios");
const qs      = require("querystring");

const app = express();
app.use(express.json());

const APP_NAME    = "BYPASS UID";
const OWNER_ID    = "VVa5LvFsyr";
const VERSION     = "1.0";
const APP_ENABLED = true;

// ─── KeyAuth: init session ────────────────────────────────────────────────────
async function keyauthInit() {
  const resp = await axios.post(
    "https://keyauth.win/api/1.2/",
    qs.stringify({ type: "init", name: APP_NAME, ownerid: OWNER_ID, ver: VERSION, hash: "backend" }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
  );
  if (!resp.data?.success || !resp.data?.sessionid)
    throw new Error("Error de inicialización con KeyAuth");
  return resp.data.sessionid;
}

// ─── KeyAuth: verificar licencia ─────────────────────────────────────────────
async function keyauthLicense(key, hwid, sessionid) {
  const resp = await axios.post(
    "https://keyauth.win/api/1.2/",
    qs.stringify({ type: "license", key, hwid, sessionid, name: APP_NAME, ownerid: OWNER_ID }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
  );
  return resp.data;
}

// ─── Extraer timestamp de expiración ─────────────────────────────────────────
function extractExpiry(data) {
  const sub = data?.info?.subscriptions?.[0];
  if (sub?.expiry && sub.expiry !== "0") return String(sub.expiry);

  const candidates = [
    data?.info?.expiry,
    data?.info?.expires,
    data?.info?.sub_expiry,
    data?.expiry,
  ];
  for (const val of candidates) {
    if (val && val !== "0" && val !== 0) return String(val);
  }
  return null;
}

// ─── Clasificar respuesta de KeyAuth ─────────────────────────────────────────
//
// IMPORTANTE: El orden de los checks importa.
// Primero verificar success=true, luego los casos de "válido pero con mensaje",
// y SOLO al final los casos de rechazo real.
//
function classifyResponse(data) {
  const raw     = (data?.message || "").toLowerCase();
  const success = !!data?.success;
  const expiry  = extractExpiry(data);

  // LOG para debug
  console.log("[CLASSIFY] success:", success, "| message:", data?.message, "| expiry:", expiry);

  // ── CASO 1: KeyAuth dice success=true → válido ──
  if (success) {
    return { valid: true, rejectionCode: null, expiry };
  }

  // ── CASO 2: Mensajes que en realidad son válidos ──
  // Key nueva usada por primera vez, HWID registrado ahora
  if (
    raw.includes("user already exists")   ||
    raw.includes("already used")          ||
    raw.includes("hwid locked")           ||
    raw.includes("device already")        ||
    raw.includes("not used")              ||  // key sin usar, primer uso
    raw.includes("registered")            ||  // recién registrado
    raw.includes("logged in")
  ) {
    return { valid: true, rejectionCode: null, expiry };
  }

  // ── CASO 3: Rechazos reales ──
  // El orden importa: verificar ban/paused/expired ANTES que hwid/invalid
  // porque algunos mensajes pueden contener múltiples palabras

  if (raw.includes("banned") || raw.includes("blacklist"))
    return { valid: false, rejectionCode: "banned",   expiry: null };

  if (raw.includes("paused") || raw.includes("disabled") || raw.includes("suspended"))
    return { valid: false, rejectionCode: "paused",   expiry: null };

  if (raw.includes("expired") || raw.includes("expir"))
    return { valid: false, rejectionCode: "expired",  expiry: null };

  // HWID mismatch: solo cuando es un conflicto REAL de dispositivo
  // "hwid mismatch" o "different device" pero NO "hwid locked" (ese es válido)
  if (
    (raw.includes("hwid") && raw.includes("mismatch")) ||
    (raw.includes("hwid") && raw.includes("wrong"))    ||
    (raw.includes("device") && raw.includes("different"))
  ) return { valid: false, rejectionCode: "hwid", expiry: null };

  if (
    raw.includes("not found")      ||
    raw.includes("does not exist") ||
    raw.includes("revoked")        ||
    raw.includes("key not")        ||
    raw.includes("invalid key")
  ) return { valid: false, rejectionCode: "notfound", expiry: null };

  // "invalid" solo si no cayó en ninguno de los casos anteriores
  if (raw.includes("invalid"))
    return { valid: false, rejectionCode: "notfound", expiry: null };

  // Desconocido — loguear para investigar
  console.log("[CLASSIFY] Mensaje no reconocido:", data?.message, "| data:", JSON.stringify(data));
  return { valid: false, rejectionCode: "unknown", expiry: null };
}

// ─── Formatear payload de expiración ─────────────────────────────────────────
function buildExpiryPayload(expiryRaw) {
  if (!expiryRaw || expiryRaw === "0") {
    return { expiryText: "Ilimitado ♾", expiryRaw: null, isLifetime: true };
  }

  const ts = parseInt(expiryRaw);
  if (isNaN(ts) || ts <= 0) {
    return { expiryText: expiryRaw, expiryRaw: null, isLifetime: false };
  }

  const nowSecs  = Math.floor(Date.now() / 1000);
  const diffSecs = ts - nowSecs;

  if (diffSecs <= 0) {
    return { expiryText: "EXPIRADO", expiryRaw: String(ts), isLifetime: false };
  }

  const days  = Math.floor(diffSecs / 86400);
  const hours = Math.floor((diffSecs % 86400) / 3600);
  const mins  = Math.floor((diffSecs % 3600) / 60);

  const date    = new Date(ts * 1000);
  const dateStr = date.toLocaleDateString("es-ES", { day: "2-digit", month: "2-digit", year: "numeric" });

  let expiryText;
  if (days > 0)        expiryText = `${dateStr} | ${days}d ${hours}h restantes`;
  else if (hours > 0)  expiryText = `${dateStr} | ${hours}h ${mins}m restantes`;
  else                 expiryText = `Vence en ${mins} minuto(s)`;

  return { expiryText, expiryRaw: String(ts), isLifetime: false };
}

// ─── GET / ───────────────────────────────────────────────────────────────────
app.get("/",           (_req, res) => res.send("Backend de Bypass Apk funcionando ✔"));
app.get("/api/ping",   (_req, res) => res.json({ ok: true }));
app.get("/api/app-status", (_req, res) => res.json({ enabled: APP_ENABLED }));

// ─── POST /api/login-key ──────────────────────────────────────────────────────
app.post("/api/login-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid       || "").trim();

  if (!key)  return res.json({ success: false, message: "Falta la clave de licencia" });
  if (!hwid) return res.json({ success: false, message: "Falta el HWID" });

  try {
    const sessionid   = await keyauthInit();
    const licenseData = await keyauthLicense(key, hwid, sessionid);

    console.log("[LOGIN] raw KeyAuth:", JSON.stringify(licenseData));

    const { valid, rejectionCode, expiry } = classifyResponse(licenseData);
    const expiryPayload = buildExpiryPayload(expiry);

    return res.json({
      success:       valid,
      message:       licenseData?.message || "",
      rejectionCode: rejectionCode,
      expiryText:    expiryPayload.expiryText,
      expiryRaw:     expiryPayload.expiryRaw,
      isLifetime:    expiryPayload.isLifetime,
    });

  } catch (e) {
    console.error("[LOGIN] Error:", e.message);
    return res.json({ success: false, message: "Error en el servidor: " + e.message });
  }
});

// ─── POST /api/verify-key ─────────────────────────────────────────────────────
app.post("/api/verify-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid       || "").trim();

  if (!key || !hwid) {
    return res.json({ success: false, rejectionCode: "unknown", message: "Faltan datos" });
  }

  try {
    const sessionid   = await keyauthInit();
    const licenseData = await keyauthLicense(key, hwid, sessionid);

    console.log("[VERIFY] raw KeyAuth:", JSON.stringify(licenseData));

    const { valid, rejectionCode, expiry } = classifyResponse(licenseData);
    const expiryPayload = buildExpiryPayload(expiry);

    return res.json({
      success:       valid,
      message:       licenseData?.message || "",
      rejectionCode: rejectionCode,
      expiryText:    expiryPayload.expiryText,
      expiryRaw:     expiryPayload.expiryRaw,
      isLifetime:    expiryPayload.isLifetime,
      offline:       false,
    });

  } catch (e) {
    console.error("[VERIFY] Error:", e.message);
    return res.json({ success: true, offline: true, rejectionCode: null, message: "Servidor no disponible" });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
