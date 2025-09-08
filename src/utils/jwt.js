const jwt = require('jsonwebtoken');

const createAccessToken = (payload) =>
    jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });

const createRefreshToken = (payload) =>
    jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

module.exports = { createAccessToken, createRefreshToken };
