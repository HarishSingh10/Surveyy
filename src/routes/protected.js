const express = require("express");
const router = express.Router();
const User = require("../models/User"); // Your Postgres User model
const authMiddleware = require("../middleware/auth");

// Get profile
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

// Update profile
router.put("/profile", authMiddleware, async (req, res) => {
    try {
        const updates = req.body; // e.g., { address: "New Delhi, India" }

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found" });

        // Fields user should NOT update
        delete updates.role;
        delete updates.refresh_token;
        delete updates.password;
        delete updates.is_verified;

        const fields = Object.keys(updates);
        if (fields.length === 0) return res.status(400).json({ message: "No valid fields to update" });

        // Build dynamic SQL for PostgreSQL
        const setQuery = fields.map((field, idx) => `${field} = $${idx + 1}`).join(", ");
        const values = fields.map((field) => updates[field]);

        // Add user id at the end for WHERE clause
        values.push(req.user.id);

        // Update the user
        await User.pool.query(
            `UPDATE users SET ${setQuery}, updated_at = NOW() WHERE id = $${values.length}`,
            values
        );

        // Fetch updated user
        const updatedUser = await User.findById(req.user.id);
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
