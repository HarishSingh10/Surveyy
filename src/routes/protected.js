const express = require("express");
const router = express.Router();
const pool = require("../config/db");

const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("../utils/cloudinary");
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
const storage = new CloudinaryStorage({
    cloudinary,
    params: {
        folder: "profile_images", // Cloudinary folder
        allowed_formats: ["jpg", "jpeg", "png", "webp"],
    },
});
const upload = multer({ storage });

// Update user profile (with image support)
router.put(
    "/update-profile",
    authMiddleware,
    upload.single("profile_image"),
    async (req, res) => {
        try {
            const updates = { ...req.body };

            // If an image was uploaded, add Cloudinary URL
            if (req.file && req.file.path) {
                updates.profile_image = req.file.path;
            }

            delete updates.role;
            delete updates.refresh_token;
            delete updates.password;
            delete updates.is_verified;

            if (Object.keys(updates).length === 0) {
                return res.status(400).json({ message: "No valid fields to update" });
            }

            const updatedUser = await User.updateById(req.user.id, updates);
            if (!updatedUser) {
                return res.status(404).json({ message: "User not found" });
            }

            const { password, refresh_token, otp, otp_expiry, ...safeUser } =
                updatedUser;

            res.json({
                message: "Profile updated successfully",
                user: safeUser,
            });
        } catch (err) {
            res
                .status(500)
                .json({ message: "Server error", error: err.message });
        }
    }
);





router.get("/forms/:branch_id", authMiddleware, async (req, res) => {
    try {
        const { branch_id } = req.params;

        if (!branch_id) {
            return res.status(400).json({ success: false, message: "Branch ID is required" });
        }

        const formsResult = await pool.query(
            `SELECT * FROM feedback_forms WHERE branch_id = $1 ORDER BY created_at DESC`,
            [branch_id]
        );

        res.json({
            success: true,
            count: formsResult.rows.length,
            forms: formsResult.rows,
        });
    } catch (err) {
        console.error("❌ Error fetching forms by branch:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});



router.post("/submit-feedback", authMiddleware, async (req, res) => {
    try {
        const { form_id, answers, overall_score } = req.body;
        const user_iid = req.user.id;

        if (!form_id || !answers || !overall_score) {
            return res.status(400).json({ success: false, message: "Missing required fields" });
        }

        if (overall_score < 1 || overall_score > 5) {
            return res.status(400).json({ success: false, message: "Overall score must be between 1 and 5" });
        }


        const feedbackResult = await pool.query(
            `INSERT INTO feedback_responses (form_id, user_iid, answers, overall_score)
             VALUES ($1, $2, $3, $4) RETURNING *`,
            [form_id, user_iid, JSON.stringify(answers), overall_score]
        );

        const feedback = feedbackResult.rows[0];


        const settingsResult = await pool.query(
            `SELECT * FROM coupon_settings WHERE type='feedback' LIMIT 1`
        );
        const settings = settingsResult.rows[0];

        let coupon = null;


        if (settings && overall_score >= settings.min_score) {
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + settings.validity_days);

            const couponCode = `FB-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;

            const couponResult = await pool.query(
                `INSERT INTO coupons (customer_id, type, code, value, expires_at)
                 VALUES ($1,$2,$3,$4,$5)
                 RETURNING *`,
                [user_iid, "feedback", couponCode, settings.value, expiresAt]
            );

            coupon = couponResult.rows[0];
        }

        res.json({
            success: true,
            message: "Feedback submitted successfully",
            feedback,
            coupon: coupon || null
        });
    } catch (err) {
        console.error("❌ Error submitting feedback:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ✅ Get all feedbacks of logged-in user (recent first)
router.get("/my-feedbacks", authMiddleware, async (req, res) => {
    try {
        const user_id = req.user.id;

        const result = await pool.query(
            `SELECT *
FROM feedback_responses
WHERE user_iid = $1
ORDER BY created_at DESC
`,
            [user_id]
        );

        res.json({
            success: true,
            count: result.rows.length,
            feedbacks: result.rows
        });
    } catch (err) {
        console.error("❌ Error fetching user feedbacks:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = router;
