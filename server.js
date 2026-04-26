const express = require("express");
const axios   = require("axios");
const qs      = require("querystring");

const app = express();
app.use(express.json());

// ─── Configuración KeyAuth ────────────────────────────────────────────────────
const APP_NAME  = "BYPASS UID";
const OWNER_ID  = "VVa5LvFsyr";
const VERSION   = "1.0";

// ─── Kill switch global ───────────────────────────────────────────────────────
const APP_ENABLED = true;

// ─── Helper: obtener sessionid de KeyAuth ─────────────────────────────────────
async function getKeyAuthSession() {
  const initResp = await axios.post(
    "https://keyauth.win/api/1.2/",
    qs.stringify({
      type:    "init",
      name:    APP_NAME,
      ownerid: OWNER_ID,
      ver:     VERSION,
      hash:    "backend"
    }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
  );
  if (!initResp.data?.success || !initResp.data?.sessionid) {
    throw new Error("Error de inicialización con KeyAuth");
  }
  return initResp.data.sessionid;
}

// ─── Helper: verificar licencia en KeyAuth ────────────────────────────────────
async function checkLicense(key, hwid, sessionid) {
  const resp = await axios.post(
    "https://keyauth.win/api/1.2/",
    qs.stringify({
      type:      "license",
      key,
      hwid,
      sessionid,
      name:      APP_NAME,
      ownerid:   OWNER_ID
    }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
  );
  return resp.data;
}

// ─── Helper: código de rechazo ────────────────────────────────────────────────
function getRejectionCode(message) {
  if (!message) return "unknown";
  const msg = message.toLowerCase();
  if (msg.includes("paused"))                           return "paused";
  if (msg.includes("ban"))                              return "banned";
  if (msg.includes("expir"))                            return "expired";
  if (msg.includes("hwid") || msg.includes("device"))   return "hwid";
  if (msg.includes("not found") || msg.includes("invalid") || msg.includes("doesn't exist"))
                                                        return "notfound";
  return "unknown";
}

// ─── Helper: calcular tiempo restante ────────────────────────────────────────
// KeyAuth devuelve la expiración dentro de licenseData (el objeto completo),
// no solo en licenseData.info — buscamos en todos los lugares posibles.
function calcExpiryInfo(licenseData) {
  // Buscar en todos los campos posibles donde KeyAuth puede meter la fecha
  const info = licenseData?.info || {};
  const rawExpiry =
    info.expiry       ??
    info.expires      ??
    info.sub_expiry   ??
    info.expiration   ??
    licenseData?.expiry ??
    null;

  // LOG dentro de la función — aquí licenseData SÍ existe
  console.log("[EXPIRY] info:", JSON.stringify(info));
  console.log("[EXPIRY] rawExpiry:", rawExpiry);

  // Sin valor o ilimitado
  if (
    rawExpiry === null      ||
    rawExpiry === undefined ||
    rawExpiry === "lifetime"||
    rawExpiry === "-1"      ||
    rawExpiry === -1        ||
    rawExpiry === 0         ||
    rawExpiry === "0"
  ) {
    return { expiryText: "Ilimitado ♾", isLifetime: true };
  }

  // Convertir a Date
  let expiryDate;
  const numVal = Number(rawExpiry);
  if (!isNaN(numVal) && numVal > 0) {
    expiryDate = new Date(numVal * 1000); // KeyAuth usa segundos Unix
  } else {
    expiryDate = new Date(String(rawExpiry));
  }

  if (isNaN(expiryDate.getTime())) {
    console.log("[EXPIRY] No se pudo parsear:", rawExpiry);
    return { expiryText: String(rawExpiry), isLifetime: false };
  }

  const diffMs = expiryDate - new Date();
  console.log("[EXPIRY] Fecha:", expiryDate.toISOString(), "| Diff ms:", diffMs);

  if (diffMs <= 0) {
    return { expiryText: "Expirada", isLifetime: false };
  }

  const totalMinutes = Math.floor(diffMs / 60000);
  const days    = Math.floor(totalMinutes / 1440);
  const hours   = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;

  let expiryText;
  if (days > 0)        expiryText = `${days} día${days !== 1 ? "s" : ""}, ${hours} hora${hours !== 1 ? "s" : ""}`;
  else if (hours > 0)  expiryText = `${hours} hora${hours !== 1 ? "s" : ""}, ${minutes} min`;
  else                 expiryText = `${minutes} minuto${minutes !== 1 ? "s" : ""}`;

  console.log("[EXPIRY] Resultado:", expiryText);
  return { expiryText, isLifetime: false };
}

// ─── GET / ───────────────────────────────────────────────────────────────────
app.get("/", (_req, res) => res.send("Backend de Bypass Apk funcionando ✔"));

// ─── GET /api/app-status ──────────────────────────────────────────────────────
app.get("/api/app-status", (_req, res) => res.json({ enabled: APP_ENABLED }));

// ─── POST /api/debug-key — Ver respuesta RAW de KeyAuth ──────────────────────
// Úsalo con Postman o curl:
// POST https://bypass-apk.onrender.com/api/debug-key
// Body: { "licenseKey": "TU_KEY", "hwid": "test123" }
app.post("/api/debug-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid || "test_hwid_debug_00000001").trim();
  try {
    const sessionid   = await getKeyAuthSession();
    const licenseData = await checkLicense(key, hwid, sessionid);
    const expiryInfo  = calcExpiryInfo(licenseData);
    return res.json({
      raw_keyauth_response: licenseData,
      expiry_calculated:    expiryInfo
    });
  } catch (e) {
    return res.json({ error: e.message });
  }
});

// ─── POST /api/login-key ──────────────────────────────────────────────────────
app.post("/api/login-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid       || "").trim();

  if (!key)  return res.json({ success: false, message: "Falta la clave de licencia" });
  if (!hwid) return res.json({ success: false, message: "Falta el HWID" });

  try {
    const sessionid   = await getKeyAuthSession();
    const licenseData = await checkLicense(key, hwid, sessionid);
    const expiryInfo  = calcExpiryInfo(licenseData);
    const rejCode     = licenseData?.success ? null : getRejectionCode(licenseData?.message);

    return res.json({
      success:       !!licenseData?.success,
      message:       licenseData?.message || "Error desconocido",
      expiryText:    expiryInfo.expiryText,
      isLifetime:    expiryInfo.isLifetime,
      rejectionCode: rejCode,
      response:      licenseData
    });
  } catch (e) {
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
    const sessionid   = await getKeyAuthSession();
    const licenseData = await checkLicense(key, hwid, sessionid);
    const valid       = !!licenseData?.success;
    const expiryInfo  = calcExpiryInfo(licenseData);
    const rejCode     = valid ? null : getRejectionCode(licenseData?.message);

    return res.json({
      success:       valid,
      message:       licenseData?.message || "Error desconocido",
      expiryText:    expiryInfo.expiryText,
      isLifetime:    expiryInfo.isLifetime,
      rejectionCode: rejCode,
      offline:       false
    });
  } catch (e) {
    return res.json({ success: true, offline: true, rejectionCode: null, message: "Servidor no disponible: " + e.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
