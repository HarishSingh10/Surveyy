const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema(
    {
        firstName: { type: String, required: true, trim: true },
        lastName: { type: String, required: true, trim: true },
        email: { type: String, required: true, unique: true, lowercase: true },
        password: { type: String, required: true, minlength: 6 },
        address: { type: String, default: "" },

        // Optional phone field
        phone: {
            type: String,
            unique: true,
            sparse: true, // allows multiple users without phone
            validate: {
                validator: function (v) {
                    if (!v || v.trim() === "") return true; // allow empty/null
                    return /^[0-9]{10}$/.test(v); // validate only if phone is provided
                },
                message: "Please enter a valid 10-digit phone number",
            },
        },

        refreshToken: { type: String, default: null },
        isVerified: { type: Boolean, default: false },
        otp: { type: String, default: null },
        otpExpiry: { type: Date, default: null },
    },
    { timestamps: true }
);

// Hash password before save
UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Compare password
UserSchema.methods.comparePassword = function (candidate) {
    return bcrypt.compare(candidate, this.password);
};

// Generate Access Token
UserSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        { id: this._id, email: this.email, phone: this.phone },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
};

// Generate Refresh Token
UserSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        { id: this._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "7d" }
    );
};

module.exports = mongoose.model("User", UserSchema);
