const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ✅ Configure Postgres connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Neon connection string
    ssl: { rejectUnauthorized: false },
});

// ✅ Create User table if it doesn't exist
const createTable = async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS coustomer (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            address VARCHAR(255) DEFAULT '',
            phone VARCHAR(15) UNIQUE,
            refresh_token TEXT DEFAULT NULL,
            is_verified BOOLEAN DEFAULT FALSE,
            otp VARCHAR(10) DEFAULT NULL,
            otp_expiry TIMESTAMP DEFAULT NULL,
            profile_image TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
    `);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback_responses (
        id SERIAL PRIMARY KEY,
        form_id INT REFERENCES feedback_forms(id) ON DELETE CASCADE,
        user_iid INT REFERENCES coustomer(id) ON DELETE CASCADE,
        answers JSONB NOT NULL,
        overall_score SMALLINT NOT NULL CHECK (overall_score BETWEEN 1 AND 5),
        created_at TIMESTAMP DEFAULT NOW()
    );
`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS referral_clicks (
        id SERIAL PRIMARY KEY,
        referral_code VARCHAR(50) NOT NULL,
        clicked_at TIMESTAMP DEFAULT NOW(),
        device_info VARCHAR(255),
        redirected_to VARCHAR(100)  


        );
    `);
};
createTable();

const User = {
    // Create a new user
    async create({ first_name, last_name, email, password, phone, address, profile_image }) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const result = await pool.query(
            `INSERT INTO coustomer (first_name, last_name, email, password, phone, address, profile_image)
             VALUES ($1, $2, $3, $4, $5, $6,$7) RETURNING *`,
            [first_name, last_name, email, hashedPassword, phone || null, address || "", profile_image || null]
        );
        return result.rows[0];
    },

    // Find user by email
    async findByEmail(email) {
        const result = await pool.query("SELECT * FROM coustomer WHERE email = $1", [email]);
        return result.rows[0];
    },

    // Find user by ID
    async findById(id) {
        const result = await pool.query("SELECT * FROM coustomer WHERE id = $1", [id]);
        return result.rows[0];
    },

    // Update user by ID
    async updateById(id, updates) {
        const fields = Object.keys(updates);
        if (fields.length === 0) return null;

        const setQuery = fields.map((field, idx) => `${field} = $${idx + 1}`).join(", ");
        const values = fields.map((field) => updates[field]);
        values.push(id);

        const result = await pool.query(
            `UPDATE coustomer SET ${setQuery}, updated_at = NOW() WHERE id = $${values.length} RETURNING *`,
            values
        );

        return result.rows[0];
    },

    // Compare password
    async comparePassword(candidate, hashedPassword) {
        return bcrypt.compare(candidate, hashedPassword);
    },

    // Generate access token
    generateAccessToken(user) {
        return jwt.sign(
            { id: user.id, email: user.email, phone: user.phone },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "15m" }
        );
    },

    // Generate refresh token
    generateRefreshToken(user) {
        return jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
    },

    // Save refresh token
    async saveRefreshToken(id, refreshToken) {
        await pool.query("UPDATE coustomer SET refresh_token = $1 WHERE id = $2", [refreshToken, id]);
    },
};

module.exports = User;
