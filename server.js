const express = require("express");
const axios = require("axios");
const qs = require("querystring");

const app = express();
app.use(express.json());

const APP_NAME = "Cruuzuid";
const OWNER_ID = "y5tsaoFToV";
const VERSION = "1.0";

app.get("/", (_req, res) => {
  res.send("Backend de Bypass Apk funcionando");
});

app.post("/api/login-key", async (req, res) => {
  // 1. Recibimos la key y el hwid que envía la app Android
  const key = (req.body.licenseKey || "").trim();
  const hwid = (req.body.hwid || "").trim(); 

  if (!key) {
    return res.json({ success: false, message: "Falta la clave de licencia" });
  }

  try {
    // Paso 1: INIT con KeyAuth
    const initBody = qs.stringify({
      type: "init",
      name: APP_NAME,
      ownerid: OWNER_ID,
      ver: VERSION,
      hash: "backend"
    });

    const initResp = await axios.post("https://keyauth.win/api/1.2/", initBody, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000
    });

    if (!initResp.data || !initResp.data.success || !initResp.data.sessionid) {
      return res.json({
        success: false,
        message: "Error de inicialización con KeyAuth",
        response: initResp.data
      });
    }

    const sessionid = initResp.data.sessionid;

    // Paso 2: LICENSE (Aquí es donde pasamos el HWID)
    const licenseBody = qs.stringify({
      type: "license",
      key: key,
      hwid: hwid, 
      sessionid: sessionid,
      name: APP_NAME,
      ownerid: OWNER_ID
    });

    const licenseResp = await axios.post("https://keyauth.win/api/1.2/", licenseBody, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000
    });

    // Devolvemos la respuesta final a la app
    return res.json({
      success: !!licenseResp.data?.success,
      message: licenseResp.data?.message || "Error desconocido",
      response: licenseResp.data // Mandamos todo el objeto por si acaso
    });

  } catch (e) {
    return res.json({ 
      success: false, 
      message: "Error en el servidor: " + e.message 
    });
  }
});

const APP_ENABLED = true;

app.get("/api/app-status", (_req, res) => {
  return res.json({
    enabled: APP_ENABLED
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
