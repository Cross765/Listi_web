import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pkg;
const app = express();
const PORT = process.env.PORT || 3000;

// Necesario para usar __dirname con ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Servir frontend desde carpeta "sitio"
app.use(express.static(path.join(__dirname, "sitio")));

// Conexión a PostgreSQL con variables de entorno (Render)
const pool = new Pool({
  host: process.env.DB_HOST || "dpg-d3elbeer433s73eppof0-a.oregon-postgres.render.com",
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || "listi_7mwu",
  user: process.env.DB_USER || "listi_7mwu_user",
  password: process.env.DB_PASSWORD || "cPEEWPBRxx4R0jnyfym6FebpEVGgRWhB",
  ssl: { rejectUnauthorized: false }
});

// --- Hash de contraseña ---
function hashPassword(password, iterations = 600000) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2_sha256$${iterations}$${salt.toString("hex")}$${dk.toString("hex")}`;
}

// --- API de registro ---
app.post("/api/register", async (req, res) => {
  const { nombre, email, password } = req.body;

  try {
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Validar contraseña
    const regexPass = /^(?=.*[0-9])(?=.*[a-zA-Z]).{8,}$/;
    if (!regexPass.test(password)) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres, incluyendo letras y números." });
    }

    // Verificar si ya existe
    const checkUser = await pool.query(
      "SELECT * FROM usuarios WHERE nombre_usuario=$1 OR correo_electronico=$2",
      [nombre, email]
    );
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: "Usuario o correo ya existente." });
    }

    // Hashear y guardar
    const hashedPassword = hashPassword(password);
    await pool.query(
      "INSERT INTO usuarios (nombre_usuario, correo_electronico, contraseña) VALUES ($1, $2, $3)",
      [nombre, email, hashedPassword]
    );

    res.status(201).json({ message: "Usuario registrado con éxito." });
  } catch (err) {
    console.error("Error en /api/register:", err);
    res.status(500).json({ error: "Error en el servidor." });
  }
});

// Cualquier ruta que no sea /api devuelve el frontend
app.get("*", (req, res) => {
  try {
    res.sendFile(path.join(__dirname, "sitio", "index.html"));
  } catch (err) {
    console.error("Error al servir index.html:", err);
    res.status(500).send("No se pudo cargar la página principal.");
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});
