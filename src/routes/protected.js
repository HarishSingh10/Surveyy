const express = require("express");
const router = express.Router();
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");

// Get profile (already exists)
router.get("/profile", authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password -refreshToken");
        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Update profile
router.put("/profile", authMiddleware, async (req, res) => {
    try {
        const updates = req.body; // contains fields to update, e.g., name, email
        const user = await User.findById(req.user.id);

        if (!user) return res.status(404).json({ message: "User not found" });

        // Optional: prevent role & refreshToken from being updated by user
        delete updates.role;
        delete updates.refreshToken;
        delete updates.password; // password should be updated via separate endpoint

        // Update fields
        Object.keys(updates).forEach((key) => {
            user[key] = updates[key];
        });

        await user.save();

        res.json({
            message: "Profile updated successfully",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
            },
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

module.exports = router;
