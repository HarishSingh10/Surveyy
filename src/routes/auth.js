const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
const authMiddleware = require("../middleware/auth");

// ✅ Postgres pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// ✅ Nodemailer transporter
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Temporary OTP stores
const otpStore = {};
const passwordResetOTP = {};

const isProd = process.env.NODE_ENV === "production";

// ----------------- Helper: Send OTP -----------------
const sendOTP = async (email, otp) => {
    await transporter.sendMail({
        from: `"Surveyy" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Your OTP Code",
        html: `<h3>Your OTP is: <b>${otp}</b></h3>`,
    });
};

// ----------------- Helper: Generate Tokens -----------------
const generateAccessToken = (user) =>
    jwt.sign({ id: user.id, email: user.email, phone: user.phone }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m",
    });

const generateRefreshToken = (user) =>
    jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

// ----------------- Register -----------------
router.post("/register", async (req, res) => {
    try {
        const { first_name, last_name, email, phone, password, confirmPassword, address } = req.body;

        if (!first_name || !last_name || !email || !phone || !password || !confirmPassword) {
            return res.status(400).json({ success: false, message: "Required fields are missing" });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, message: "Passwords do not match" });
        }

        const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ success: false, message: "Email already in use" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = {
            otp,
            expiresAt: Date.now() + 10 * 60 * 1000,
            data: { first_name, last_name, email, password, phone, address },
        };

        await sendOTP(email, otp);
        res.status(200).json({ success: true, message: "OTP sent to " + email });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Verify Signup OTP -----------------
router.post("/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        const record = otpStore[email];
        if (!record) return res.status(400).json({ success: false, message: "OTP not found" });

        if (Date.now() > record.expiresAt) {
            delete otpStore[email];
            return res.status(400).json({ success: false, message: "OTP expired" });
        }
        if (record.otp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });

        const hashedPassword = await bcrypt.hash(record.data.password, 10);

        const newUser = await pool.query(
            `INSERT INTO users (first_name, last_name, email, password, phone, address, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING id, first_name, last_name, email, phone, address`,
            [record.data.first_name, record.data.last_name, record.data.email, hashedPassword, record.data.phone, record.data.address]
        );

        const user = newUser.rows[0];
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [refreshToken, user.id]);

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            sameSite: "strict",
            path: "/api/auth/refresh",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        delete otpStore[email];
        res.status(201).json({ success: true, message: "User registered successfully", user, accessToken, refreshToken });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Login (Step 1: Request OTP) -----------------
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000, data: { userId: user.id } };

        await sendOTP(email, otp);
        res.status(200).json({ success: true, message: "OTP sent to email for verification" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Login (Step 2: Verify OTP) -----------------
router.post("/login-verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        const record = otpStore[email];
        if (!record) return res.status(400).json({ success: false, message: "OTP not found" });

        if (Date.now() > record.expiresAt) {
            delete otpStore[email];
            return res.status(400).json({ success: false, message: "OTP expired" });
        }
        if (record.otp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });

        const result = await pool.query("SELECT * FROM users WHERE id = $1", [record.data.userId]);
        const user = result.rows[0];
        delete otpStore[email];

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [refreshToken, user.id]);

        res.json({
            success: true,
            message: "Login successful",
            user: { id: user.id, first_name: user.first_name, last_name: user.last_name, email: user.email, phone: user.phone },
            accessToken,
            refreshToken,
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Forgot Password -----------------
router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email is required" });

        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        passwordResetOTP[email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000 };

        await sendOTP(email, otp);
        res.status(200).json({ success: true, message: "OTP sent to email" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Forgot Password: Verify OTP -----------------
router.post("/forgot-password-verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        const record = passwordResetOTP[email];
        if (!record) return res.status(400).json({ success: false, message: "OTP not found" });

        if (Date.now() > record.expiresAt) {
            delete passwordResetOTP[email];
            return res.status(400).json({ success: false, message: "OTP expired" });
        }
        if (record.otp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });

        const resetToken = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
        res.json({ success: true, message: "OTP verified. You can now reset your password.", resetToken });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Reset Password -----------------
router.post("/reset-password", async (req, res) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        const resetToken = req.headers["authorization"]?.split(" ")[1];
        if (!resetToken) return res.status(401).json({ success: false, message: "Unauthorized" });
        if (!newPassword || !confirmPassword) return res.status(400).json({ success: false, message: "Both fields required" });
        if (newPassword !== confirmPassword) return res.status(400).json({ success: false, message: "Passwords do not match" });

        const decoded = jwt.verify(resetToken, process.env.ACCESS_TOKEN_SECRET);
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashedPassword, decoded.email]);
        delete passwordResetOTP[decoded.email];

        res.json({ success: true, message: "Password reset successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Refresh Access Token -----------------
router.post("/refresh", async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
        if (!refreshToken) return res.status(401).json({ success: false, message: "No refresh token provided" });

        const result = await pool.query("SELECT * FROM users WHERE refresh_token = $1", [refreshToken]);
        const user = result.rows[0];
        if (!user) return res.status(403).json({ success: false, message: "Invalid refresh token" });

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
            if (err || user.id !== decoded.id) return res.status(403).json({ success: false, message: "Invalid or expired refresh token" });

            const newAccessToken = generateAccessToken(user);
            const newRefreshToken = generateRefreshToken(user);

            await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [newRefreshToken, user.id]);

            res.cookie("refreshToken", newRefreshToken, {
                httpOnly: true,
                sameSite: "strict",
                path: "/api/auth/refresh",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });

            res.json({ success: true, accessToken: newAccessToken, refreshToken: newRefreshToken });
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Logout -----------------
router.post("/logout", async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
        if (refreshToken) {
            await pool.query("UPDATE users SET refresh_token = NULL WHERE refresh_token = $1", [refreshToken]);
        }

        res.clearCookie("refreshToken", { path: "/api/auth/refresh" });
        res.json({ success: true, message: "Logged out successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

module.exports = router;
