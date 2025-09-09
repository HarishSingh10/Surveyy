const express = require("express");
const router = express.Router();
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const isProd = process.env.NODE_ENV === "production";

// ----------------- OTP Email Setup -----------------
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,        // secure SSL port
    secure: true,     // true for port 465
    auth: {
        user: process.env.SMTP_USER, // your gmail
        pass: process.env.SMTP_PASS, // 16-char Gmail App Password
    },
});

// Verify transporter connection
transporter.verify((err, success) => {
    if (err) console.error("SMTP connection error:", err);
    else console.log("SMTP ready to send messages");
});

// In-memory OTP store (for demo; use Redis/DB in production)
const otpStore = {};

// ----------------- Helper: Send OTP -----------------
const sendOTP = async (email, subject, otp) => {
    await transporter.sendMail({
        from: `"Surveyy" <${process.env.SMTP_USER}>`,
        to: email,
        subject,
        text: `Your OTP is ${otp}`,
        html: `<h3>Your OTP is: <b>${otp}</b></h3>`,
    });
};

// ----------------- Register (send OTP) -----------------
router.post("/register", async (req, res) => {
    try {
        const { firstName, lastName, email, password, address } = req.body;
        if (!firstName || !lastName || !email || !password || !address) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const exists = await User.findOne({ email });
        if (exists) return res.status(409).json({ message: "Email already in use" });

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, data: { firstName, lastName, email, password, address } };

        await sendOTP(email, "Verify your account - OTP", otp);

        res.status(200).json({ message: "OTP sent to email" });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ----------------- Verify OTP & Create User -----------------
router.post("/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

        const record = otpStore[email];
        if (!record || record.otp !== otp) return res.status(400).json({ message: "Invalid or expired OTP" });

        const user = await User.create(record.data);
        delete otpStore[email];

        res.status(201).json({
            message: "User registered successfully",
            user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, address: user.address },
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ----------------- Login -----------------
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Email and password required" });

        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save();

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: "strict",
            path: "/api/auth/refresh",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({
            message: "Logged in",
            user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, address: user.address },
            accessToken,
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ----------------- Update Profile -----------------
router.put("/update-profile", async (req, res) => {
    try {
        const { userId, firstName, lastName, address } = req.body;
        if (!userId) return res.status(400).json({ message: "User ID required" });

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        if (firstName) user.firstName = firstName;
        if (lastName) user.lastName = lastName;
        if (address) user.address = address;

        await user.save();

        res.json({ message: "Profile updated", user });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ----------------- Forgot Password (send OTP) -----------------
router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email required" });

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, data: { userId: user._id } };

        await sendOTP(email, "Password Reset OTP", otp);

        res.status(200).json({ message: "OTP sent to email for password reset" });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ----------------- Reset Password (verify OTP) -----------------
router.post("/reset-password", async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword)
            return res.status(400).json({ message: "Email, OTP and new password required" });

        const record = otpStore[email];
        if (!record || record.otp !== otp)
            return res.status(400).json({ message: "Invalid or expired OTP" });

        const user = await User.findById(record.data.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        user.password = newPassword; // assuming pre-save hook hashes password
        await user.save();

        delete otpStore[email];

        res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

module.exports = router;
