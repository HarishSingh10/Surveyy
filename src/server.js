require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { Pool } = require("pg");

const authRoutes = require("./routes/auth");
const protectedRoutes = require("./routes/protected");

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
        origin: "http://localhost:3000", // your frontend URL
        credentials: true, // allow cookies to be sent
    })
);

// ✅ PostgreSQL connection (Neon DB)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }, // required for Neon
});

pool
    .connect()
    .then(() => console.log("✅ Connected to PostgreSQL (Neon)"))
    .catch((err) => console.error("❌ PostgreSQL connection error:", err));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/protected", protectedRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
