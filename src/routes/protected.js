const express = require("express");
const router = express.Router();
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");

// Get profile
router.get("/profile", authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password -refreshToken");
        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Update profile
router.put("/profile", authMiddleware, async (req, res) => {
    try {
        const updates = req.body; // example: { address: "New Delhi, India" }
        const user = await User.findById(req.user.id);

        if (!user) return res.status(404).json({ message: "User not found" });

        // Fields user should NOT update
        delete updates.role;
        delete updates.refreshToken;
        delete updates.password;
        delete updates.isVerified;

        // Apply updates safely
        Object.keys(updates).forEach((key) => {
            user[key] = updates[key];
        });

        await user.save();

        res.json({
            message: "Profile updated successfully",
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                address: user.address, // 👈 include updated address
                isVerified: user.isVerified
            },
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

module.exports = router;
