import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import Brevo from "sib-api-v3-sdk";

const { Pool } = pkg;
const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "sitio")));

// =======================
// 🔗 Conexión a PostgreSQL
// =======================
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false }
});

// =======================
// 🔐 Función para hash
// =======================
function hashPassword(password, iterations = 600000) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2_sha256$${iterations}$${salt.toString("hex")}$${dk.toString("hex")}`;
}

// =======================
// ✉️ Configuración Brevo API
// =======================
const brevoClient = Brevo.ApiClient.instance;
const apiKey = brevoClient.authentications["api-key"];
apiKey.apiKey = process.env.BREVO_API_KEY;
const brevoAPI = new Brevo.TransactionalEmailsApi();

async function enviarCorreoVerificacion(nombre, email, codigo) {
  try {
    await brevoAPI.sendTransacEmail({
      sender: { email: "oficiallisti@gmail.com", name: "LISTI" },
      to: [{ email, name: nombre }],
      subject: "Código de verificación - LISTI",
      htmlContent: `
        <h2>Hola ${nombre},</h2>
        <p>Tu código de verificación para LISTI es:</p>
        <h1 style="color:#007bff">${codigo}</h1>
        <p>Por favor ingrésalo en la página para activar tu cuenta.</p>
      `
    });
    console.log(`✅ Correo de verificación enviado a ${email}`);
  } catch (error) {
    console.error("❌ Error al enviar correo con Brevo:", error);
  }
}

// =======================
// 📬 Ruta: Registro
// =======================
app.post("/api/register", async (req, res) => {
  const { nombre, email, password } = req.body;

  try {
    if (!nombre || !email || !password)
      return res.status(400).json({ error: "Todos los campos son obligatorios." });

    const regexPass = /^(?=.*[0-9])(?=.*[a-zA-Z]).{8,}$/;
    if (!regexPass.test(password))
      return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres, incluyendo letras y números." });

    const existe = await pool.query(
      "SELECT * FROM usuarios WHERE nombre_usuario=$1 OR correo_electronico=$2",
      [nombre, email]
    );
    if (existe.rows.length > 0)
      return res.status(400).json({ error: "Usuario o correo ya existente." });

    const hashedPassword = hashPassword(password);
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      "INSERT INTO usuarios (nombre_usuario, correo_electronico, contraseña, codigo_verificacion, verificado) VALUES ($1, $2, $3, $4, false)",
      [nombre, email, hashedPassword, codigo]
    );

    await enviarCorreoVerificacion(nombre, email, codigo);

    res.status(201).json({
      message: "Usuario registrado. Se envió un código de verificación a tu correo."
    });
  } catch (err) {
    console.error("Error en /api/register:", err);
    res.status(500).json({ error: "Error en el servidor." });
  }
});

// =======================
// 🔍 Ruta: Verificar código
// =======================
app.post("/api/verificar", async (req, res) => {
  const { email, codigo } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM usuarios WHERE correo_electronico=$1 AND codigo_verificacion=$2",
      [email, codigo]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Código o correo incorrecto." });

    await pool.query(
      "UPDATE usuarios SET verificado=true, codigo_verificacion=NULL WHERE correo_electronico=$1",
      [email]
    );

    res.json({ message: "Cuenta verificada correctamente." });
  } catch (err) {
    console.error("Error en /api/verificar:", err);
    res.status(500).json({ error: "Error en el servidor." });
  }
});

// =======================
// 🌐 Servir Frontend
// =======================
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "sitio", "index.html"));
});


app.listen(PORT, () => console.log(`✅ Servidor corriendo en puerto ${PORT}`));
