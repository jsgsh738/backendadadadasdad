import express from "express";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

const { Pool } = pkg;
const app = express();

// 🔑 Подключение к базе Neon
const pool = new Pool({
  connectionString: "postgres://neondb_owner:npg_Vfh1dSrExi2a@ep-silent-mountain-aduh9z3d-pooler.c-2.us-east-1.aws.neon.tech/neondb",
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = "kernel_secret_2025";

app.use(cors());
app.use(express.json());

/* 📌 Автосоздание таблиц */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      display_name TEXT,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user'
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      price INTEGER NOT NULL,
      discount INTEGER DEFAULT 0,
      pinned BOOLEAN DEFAULT false,
      type TEXT CHECK (type IN ('download','buy')) NOT NULL,
      file_url TEXT,
      funpay_url TEXT,
      star_url TEXT,
      created_at TIMESTAMP DEFAULT now()
    );
  `);

  console.log("✅ Таблицы проверены/созданы");
}
initDb();

/* 📌 Middleware */
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

/* 📌 Регистрация */
app.post("/api/register", async (req, res) => {
  const { email, password, displayName } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (email, display_name, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING id,email,role,display_name",
      [email, displayName, hash, email === "egorgudyma063@gmail.com" ? "admin" : "user"]
    );
    res.json(result.rows[0]);
  } catch {
    res.status(400).json({ error: "Email уже существует" });
  }
});

/* 📌 Логин */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (result.rows.length === 0) return res.status(401).json({ error: "Неверный email" });

  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Неверный пароль" });

  // Сессия живёт 7 дней
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: "7d" });

  res.json({ token, user: { id: user.id, email: user.email, role: user.role, displayName: user.display_name } });
});

/* 📌 Logout (чисто для фронта) */
app.post("/api/logout", (req, res) => {
  res.json({ success: true, message: "Вы вышли из аккаунта. Удалите токен на клиенте." });
});

/* 📌 Текущий пользователь */
app.get("/api/me", auth(), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,email,display_name,role FROM users WHERE id=$1",
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Пользователь не найден" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

/* 📌 Получение товаров */
app.get("/api/products", async (req, res) => {
  const result = await pool.query("SELECT * FROM products ORDER BY pinned DESC, created_at DESC");
  res.json(result.rows);
});

/* 📌 Добавление товара */
app.post("/api/products", auth("admin"), async (req, res) => {
  const { title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl } = req.body;
  const result = await pool.query(
    `INSERT INTO products (title, description, price, discount, pinned, type, file_url, funpay_url, star_url)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl]
  );
  res.json(result.rows[0]);
});

/* 📌 Редактирование товара */
app.put("/api/products/:id", auth("admin"), async (req, res) => {
  const { title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl } = req.body;
  const result = await pool.query(
    `UPDATE products SET title=$1,description=$2,price=$3,discount=$4,pinned=$5,type=$6,
     file_url=$7,funpay_url=$8,star_url=$9 WHERE id=$10 RETURNING *`,
    [title, description, price, discount, pinned, type, fileUrl, funpayUrl, starUrl, req.params.id]
  );
  res.json(result.rows[0]);
});

/* 📌 Удаление товара */
app.delete("/api/products/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM products WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

/* 📌 Сделать админом */
app.post("/api/make-admin", auth("admin"), async (req, res) => {
  const { email } = req.body;
  const result = await pool.query("UPDATE users SET role='admin' WHERE email=$1 RETURNING id,email,role", [email]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Пользователь не найден" });
  res.json(result.rows[0]);
});

/* 📌 Смена пароля */
app.post("/api/change-password", auth(), async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Пароль обязателен" });

  const hash = await bcrypt.hash(password, 10);
  await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, req.user.id]);

  res.json({ success: true, message: "Пароль успешно изменён" });
});

/* 📌 Проверка backend */
app.get("/", (req, res) => {
  res.send("✅ Kernel backend работает");
});

app.listen(3000, () => console.log("🚀 API запущено на http://localhost:3000"));
