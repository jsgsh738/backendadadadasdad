import express from "express";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

const { Pool } = pkg;
const app = express();

// 🔑 подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.postgresql://neondb_owner:npg_Vfh1dSrExi2a@ep-silent-mountain-aduh9z3d-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require, // Render или Neon
  ssl: { rejectUnauthorized: false }
});

// 🔑 секрет для JWT токенов
const JWT_SECRET = process.env.JWT_SECRET || "kernel_super_secret_2025";

app.use(cors());
app.use(express.json());

// --- middleware для проверки токена ---
function auth(role = null) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Нет токена" });
    try {
      const decoded = jwt.verify(header.split(" ")[1], JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).json({ error: "Нет доступа" });
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: "Неверный токен" });
    }
  };
}

// --- регистрация ---
app.post("/api/register", async (req, res) => {
  const { email, password, displayName } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (email, display_name, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING id,email,role,display_name",
      [email, displayName, hash, email === "egorgudyma063@gmail.com" ? "admin" : "user"]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(400).json({ error: "Email уже существует" });
  }
});

// --- логин ---
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (result.rows.length === 0) return res.status(401).json({ error: "Неверный email" });

  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Неверный пароль" });

  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, email: user.email, role: user.role, displayName: user.display_name } });
});

// --- список товаров ---
app.get("/api/products", async (req, res) => {
  const result = await pool.query("SELECT * FROM products ORDER BY pinned DESC, created_at DESC");
  res.json(result.rows);
});

// --- добавить товар (только админ) ---
app.post("/api/products", auth("admin"), async (req, res) => {
  const { title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl } = req.body;
  const result = await pool.query(
    `INSERT INTO products (title, description, price, discount, pinned, type, file_url, funpay_url, star_url) 
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl]
  );
  res.json(result.rows[0]);
});

// --- редактировать товар ---
app.put("/api/products/:id", auth("admin"), async (req, res) => {
  const { title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl } = req.body;
  const result = await pool.query(
    `UPDATE products SET title=$1,description=$2,price=$3,discount=$4,pinned=$5,type=$6,
     file_url=$7,funpay_url=$8,star_url=$9 WHERE id=$10 RETURNING *`,
    [title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl, req.params.id]
  );
  res.json(result.rows[0]);
});

// --- удалить товар ---
app.delete("/api/products/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM products WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// --- сделать пользователя админом ---
app.post("/api/make-admin", auth("admin"), async (req, res) => {
  const { email } = req.body;
  const result = await pool.query("UPDATE users SET role='admin' WHERE email=$1 RETURNING id,email,role", [email]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Пользователь не найден" });
  res.json(result.rows[0]);
});

app.listen(3000, () => console.log("✅ API running on http://localhost:3000"));
