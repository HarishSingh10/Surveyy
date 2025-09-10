const express = require("express");
const router = express.Router();
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const authMiddleware = require("../middleware/auth");

// Configure transporter
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Temporary OTP store
const otpStore = {}; // { email: { otp, expiresAt, data } }

// ----------------- Helper: Send OTP -----------------
const sendOTP = async (email, otp) => {
    await transporter.sendMail({
        from: `"Surveyy" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Your OTP Code",
        html: `<h3>Your OTP is: <b>${otp}</b></h3>`,
    });
};

// ----------------- Register -----------------
router.post("/register", async (req, res) => {
    try {
        const { firstName, lastName, email, phone, password, confirmPassword, address } = req.body;

        // ✅ Validation (address is now optional)
        if (!firstName || !lastName || !email || !phone || !password || !confirmPassword) {
            return res.status(400).json({ success: false, message: "Required fields are missing" });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, message: "Passwords do not match" });
        }

        const exists = await User.findOne({ email });
        if (exists) {
            return res.status(409).json({ success: false, message: "Email already in use" });
        }

        // ✅ Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // ✅ Store OTP with optional address + phone
        otpStore[email] = {
            otp,
            expiresAt: Date.now() + 10 * 60 * 1000,
            data: {
                firstName,
                lastName,
                email,
                password,
                phone: phone && phone.trim() !== "" ? phone : undefined,
                address: address && address.trim() !== "" ? address : undefined, // <- optional address
            },
        };





        await sendOTP(email, otp);

        res.status(200).json({ success: true, message: "OTP sent to " + email });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});
const isProd = process.env.NODE_ENV === "production";

// ----------------- Verify Signup OTP -----------------
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

        if (record.otp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }

        // ✅ Create user from stored data
        const user = await User.create(record.data);

        // ✅ Mark verified
        user.isVerified = true;

        // ✅ Generate tokens
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;

        await user.save();

        // ✅ Store refresh token in cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            // secure: isProd,
            sameSite: "strict",
            path: "/api/auth/refresh",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        // ✅ Clean up OTP
        delete otpStore[email];

        // ✅ Respond with tokens
        res.status(201).json({
            success: true,
            message: "User registered successfully",
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone,
                address: user.address,
            },
            accessToken,
            refreshToken,
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ----------------- Login (Step 1: Request OTP) -----------------
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000, data: { userId: user._id } };

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

        const user = await User.findById(record.data.userId);
        delete otpStore[email];

        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save();

        res.json({
            success: true,
            message: "Login successful",
            user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, phone: user.phone },
            accessToken,
            refreshToken,
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

module.exports = router;







const passwordResetOTP = {};

router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email is required" });

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        passwordResetOTP[email] = {
            otp,
            expiresAt: Date.now() + 10 * 60 * 1000,
        };

        await transporter.sendMail({
            from: `"Surveyy" <${process.env.SMTP_USER}>`,
            to: email,
            subject: "Password Reset OTP",
            html: `<h3>Your password reset OTP is: <b>${otp}</b></h3>`,
        });

        res.status(200).json({ success: true, message: "OTP sent to email" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});
// ----------------- Forgot Password: Verify OTP -----------------
router.post("/forgot-password-verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ success: false, message: "Email and OTP are required" });
        }

        const record = passwordResetOTP[email];
        if (!record) return res.status(400).json({ success: false, message: "OTP not found" });
        if (Date.now() > record.expiresAt) {
            delete passwordResetOTP[email];
            return res.status(400).json({ success: false, message: "OTP expired" });
        }
        if (record.otp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });

        // OTP verified → allow password reset
        // You can optionally generate a temporary token to authorize password reset
        const resetToken = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

        res.json({
            success: true,
            message: "OTP verified. You can now reset your password.",
            resetToken
        });

    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});
// ----------------- Reset Password -----------------
router.post("/reset-password", async (req, res) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        const resetToken = req.headers["authorization"]?.split(" ")[1]; // Bearer token

        if (!resetToken) return res.status(401).json({ success: false, message: "Unauthorized" });
        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ success: false, message: "Both fields are required" });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: "Passwords do not match" });
        }

        const decoded = jwt.verify(resetToken, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findOne({ email: decoded.email });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        user.password = newPassword;
        await user.save();

        // Delete OTP after reset
        delete passwordResetOTP[decoded.email];

        res.json({ success: true, message: "Password reset successfully" });

    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});
