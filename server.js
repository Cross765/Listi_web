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

// Necesario para __dirname en ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "sitio"))); // servir frontend

// Conexión a PostgreSQL (Render)
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false }
});

// --- Hash contraseña ---
function hashPassword(password, iterations = 600000) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2_sha256$${iterations}$${salt.toString("hex")}$${dk.toString("hex")}`;
}

// --- Ruta API ---
app.post("/api/register", async (req, res) => {
  const { nombre, email, password } = req.body;

  try {
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    const regexPass = /^(?=.*[0-9])(?=.*[a-zA-Z]).{8,}$/;
    if (!regexPass.test(password)) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres, incluyendo letras y números." });
    }

    const checkUser = await pool.query(
      "SELECT * FROM usuarios WHERE nombre_usuario=$1 OR correo_electronico=$2",
      [nombre, email]
    );
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: "Usuario o correo ya existente." });
    }

    const hashedPassword = hashPassword(password);

    await pool.query(
      "INSERT INTO usuarios (nombre_usuario, correo_electronico, contraseña) VALUES ($1, $2, $3)",
      [nombre, email, hashedPassword]
    );

    res.status(201).json({ message: "Usuario registrado con éxito." });
  } catch (err) {
    console.error("Error en registro:", err);
    res.status(500).json({ error: "Error en el servidor." });
  }
});

// Render sirve index.html como root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "sitio", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
