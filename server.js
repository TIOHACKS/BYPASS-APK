const express = require("express");
const axios   = require("axios");
const qs      = require("querystring");
console.log("KeyAuth info completo:", JSON.stringify(licenseData?.info));
console.log("KeyAuth respuesta completa:", JSON.stringify(licenseData));

const app = express();
app.use(express.json());

// ─── Configuración KeyAuth ────────────────────────────────────────────────────
const APP_NAME  = "BYPASS UID";
const OWNER_ID  = "VVa5LvFsyr";
const VERSION   = "1.0";

// ─── Kill switch global ───────────────────────────────────────────────────────
const APP_ENABLED = true;

// ─── Helper: obtener sessionid de KeyAuth ────────────────────────────────────
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
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000
    }
  );

  if (!initResp.data?.success || !initResp.data?.sessionid) {
    throw new Error("Error de inicialización con KeyAuth");
  }

  return initResp.data.sessionid;
}

// ─── Helper: verificar licencia en KeyAuth ────────────────────────────────────
async function checkLicense(key, hwid, sessionid) {
  const licenseResp = await axios.post(
    "https://keyauth.win/api/1.2/",
    qs.stringify({
      type:      "license",
      key:       key,
      hwid:      hwid,
      sessionid: sessionid,
      name:      APP_NAME,
      ownerid:   OWNER_ID
    }),
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000
    }
  );
  return licenseResp.data;
}

// ─── Helper: mapear mensaje de KeyAuth a código de motivo ────────────────────
function getRejectionCode(message) {
  if (!message) return "unknown";
  const msg = message.toLowerCase();
  if (msg.includes("paused"))                          return "paused";
  if (msg.includes("ban"))                             return "banned";
  if (msg.includes("expir"))                           return "expired";
  if (msg.includes("hwid") || msg.includes("device"))  return "hwid";
  if (
    msg.includes("not found") ||
    msg.includes("invalid")   ||
    msg.includes("doesn't exist")
  )                                                    return "notfound";
  return "unknown";
}

// ─── Helper: calcular tiempo restante de suscripción ─────────────────────────
//
// KeyAuth devuelve el campo "expiry" en el objeto "info" con formato:
//   Unix timestamp (número)  →  ej: 1751328000
//   O string con fecha       →  ej: "2025-06-30 12:00:00"
//   O el string "lifetime"   →  key sin vencimiento
//
// Devuelve un objeto:
//   { expiryText: "12 días, 4 horas", isLifetime: false, expiredAt: null }
//   { expiryText: "Ilimitado ♾",      isLifetime: true,  expiredAt: null }
//   { expiryText: "Expirada",         isLifetime: false, expiredAt: <Date> }
//
function calcExpiryInfo(info) {
  // Sin info o key lifetime
  if (!info) {
    return { expiryText: "Ilimitado ♾", isLifetime: true, expiredAt: null };
  }

  const rawExpiry = info.expiry || info.expires || null;

  // KeyAuth a veces devuelve "lifetime" o "-1" para ilimitado
  if (
    !rawExpiry ||
    rawExpiry === "lifetime" ||
    rawExpiry === "-1" ||
    rawExpiry === -1 ||
    rawExpiry === 0  ||
    rawExpiry === "0"
  ) {
    return { expiryText: "Ilimitado ♾", isLifetime: true, expiredAt: null };
  }

  // Convertir a Date
  let expiryDate;

  if (typeof rawExpiry === "number" || /^\d+$/.test(String(rawExpiry))) {
    // Unix timestamp en segundos
    expiryDate = new Date(Number(rawExpiry) * 1000);
  } else {
    // String de fecha — intentar parsear directamente
    expiryDate = new Date(rawExpiry);
  }

  if (isNaN(expiryDate.getTime())) {
    // No se pudo parsear → devolver el valor crudo
    return { expiryText: String(rawExpiry), isLifetime: false, expiredAt: null };
  }

  const now       = new Date();
  const diffMs    = expiryDate - now;

  if (diffMs <= 0) {
    return { expiryText: "Expirada", isLifetime: false, expiredAt: expiryDate };
  }

  // Calcular días, horas y minutos restantes
  const totalMinutes = Math.floor(diffMs / 60000);
  const days         = Math.floor(totalMinutes / 1440);
  const hours        = Math.floor((totalMinutes % 1440) / 60);
  const minutes      = totalMinutes % 60;

  let expiryText = "";

  if (days > 0) {
    expiryText = `${days} día${days !== 1 ? "s" : ""}, ${hours} hora${hours !== 1 ? "s" : ""}`;
  } else if (hours > 0) {
    expiryText = `${hours} hora${hours !== 1 ? "s" : ""}, ${minutes} min`;
  } else {
    expiryText = `${minutes} minuto${minutes !== 1 ? "s" : ""}`;
  }

  return { expiryText, isLifetime: false, expiredAt: null };
}

// ─── GET / ────────────────────────────────────────────────────────────────────
app.get("/", (_req, res) => {
  res.send("Backend de Bypass Apk funcionando ✔");
});

// ─── GET /api/app-status — Kill switch global ─────────────────────────────────
app.get("/api/app-status", (_req, res) => {
  return res.json({ enabled: APP_ENABLED });
});

// ─── POST /api/login-key — Login inicial ──────────────────────────────────────
app.post("/api/login-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid       || "").trim();

  if (!key)  return res.json({ success: false, message: "Falta la clave de licencia" });
  if (!hwid) return res.json({ success: false, message: "Falta el HWID" });

  try {
    const sessionid   = await getKeyAuthSession();
    const licenseData = await checkLicense(key, hwid, sessionid);

    const expiryInfo    = calcExpiryInfo(licenseData?.info);
    const rejectionCode = licenseData?.success ? null : getRejectionCode(licenseData?.message);

    return res.json({
      success:       !!licenseData?.success,
      message:       licenseData?.message || "Error desconocido",
      expiryText:    expiryInfo.expiryText,     // "12 días, 4 horas" o "Ilimitado ♾"
      isLifetime:    expiryInfo.isLifetime,
      rejectionCode: rejectionCode,
      response:      licenseData
    });

  } catch (e) {
    return res.json({
      success: false,
      message: "Error en el servidor: " + e.message
    });
  }
});

// ─── POST /api/verify-key — Verificación en cada apertura de la app ───────────
app.post("/api/verify-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid       || "").trim();

  if (!key || !hwid) {
    return res.json({ success: false, rejectionCode: "unknown", message: "Faltan datos" });
  }

  try {
    const sessionid   = await getKeyAuthSession();
    const licenseData = await checkLicense(key, hwid, sessionid);

    const valid         = !!licenseData?.success;
    const expiryInfo    = calcExpiryInfo(licenseData?.info);
    const rejectionCode = valid ? null : getRejectionCode(licenseData?.message);

    return res.json({
      success:       valid,
      message:       licenseData?.message || "Error desconocido",
      expiryText:    expiryInfo.expiryText,
      isLifetime:    expiryInfo.isLifetime,
      rejectionCode: rejectionCode,
      offline:       false
    });

  } catch (e) {
    return res.json({
      success:       true,
      offline:       true,
      rejectionCode: null,
      message:       "Servidor no disponible: " + e.message
    });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
