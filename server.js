
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

  if (!key) {
    return res.json({ success: false, message: "Falta la clave de licencia" });
  }
  if (!hwid) {
    return res.json({ success: false, message: "Falta el HWID" });
  }

  try {
    const sessionid    = await getKeyAuthSession();
    const licenseData  = await checkLicense(key, hwid, sessionid);

    // Extraer fecha de expiración si está disponible
    const expiryText = licenseData?.info?.expiry || "Ilimitado";

    return res.json({
      success:    !!licenseData?.success,
      message:    licenseData?.message || "Error desconocido",
      expiryText: expiryText,
      response:   licenseData
    });

  } catch (e) {
    return res.json({
      success: false,
      message: "Error en el servidor: " + e.message
    });
  }
});

// ─── POST /api/verify-key — Verificación en cada apertura de la app ───────────
//
// La app llama este endpoint cada vez que se abre.
// Si la key fue eliminada, baneada o pausada en KeyAuth → success: false
// La app entonces borra la sesión y manda al usuario al login.
//
app.post("/api/verify-key", async (req, res) => {
  const key  = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid       || "").trim();

  if (!key || !hwid) {
    return res.json({ success: false, message: "Faltan datos (key o hwid)" });
  }

  try {
    const sessionid   = await getKeyAuthSession();
    const licenseData = await checkLicense(key, hwid, sessionid);

    const valid      = !!licenseData?.success;
    const expiryText = licenseData?.info?.expiry || "Ilimitado";

    return res.json({
      success:    valid,
      message:    licenseData?.message || "Error desconocido",
      expiryText: expiryText,
      offline:    false
    });

  } catch (e) {
    // Si NUESTRO servidor falla (Render dormido, sin internet, etc.)
    // devolvemos offline: true para que la app decida si bloquear o no.
    // En MainActivity.java configuramos: si offline=true → dejar pasar.
    return res.json({
      success: true,
      offline: true,
      message: "Servidor no disponible temporalmente: " + e.message
    });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
