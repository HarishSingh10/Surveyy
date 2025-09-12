const express = require("express");
const router = express.Router();
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");

// Get user profile
router.get("/profile", authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found" });

        // Remove sensitive fields
        const { password, refresh_token, otp, otp_expiry, ...safeUser } = user;
        res.json({ user: safeUser });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Update user profile
router.put("/update-profile", authMiddleware, async (req, res) => {
    try {
        const updates = { ...req.body };

        // Restrict sensitive updates
        delete updates.role;
        delete updates.refresh_token;
        delete updates.password;
        delete updates.is_verified;

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: "No valid fields to update" });
        }

        const updatedUser = await User.updateById(req.user.id, updates);
        if (!updatedUser) return res.status(404).json({ message: "User not found" });

        const { password, refresh_token, otp, otp_expiry, ...safeUser } = updatedUser;
        res.json({
            message: "Profile updated successfully",
            user: safeUser,
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

module.exports = router;
