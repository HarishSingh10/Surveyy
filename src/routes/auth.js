const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { createAccessToken, createRefreshToken } = require('../utils/jwt');
const jwt = require('jsonwebtoken');

const isProd = process.env.NODE_ENV === 'production';

// REGISTER
router.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ message: 'All fields required' });

        const exists = await User.findOne({ email });
        if (exists) return res.status(409).json({ message: 'Email already in use' });

        const user = await User.create({ name, email, password });

        const accessToken = createAccessToken({ id: user._id, email: user.email });
        const refreshToken = createRefreshToken({ id: user._id });
        user.refreshToken = refreshToken;
        await user.save();

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: 'strict',
            path: '/api/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.status(201).json({
            message: 'User registered',
            user: { id: user._id, name: user.name, email: user.email },
            accessToken,
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// LOGIN
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ message: 'Email and password required' });

        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password)))
            return res.status(401).json({ message: 'Invalid credentials' });

        const accessToken = createAccessToken({ id: user._id, email: user.email });
        const refreshToken = createRefreshToken({ id: user._id });
        user.refreshToken = refreshToken;
        await user.save();

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: 'strict',
            path: '/api/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({
            message: 'Logged in',
            user: { id: user._id, name: user.name, email: user.email },
            accessToken,
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// REFRESH
router.post('/refresh', async (req, res) => {
    try {
        const token = req.cookies?.refreshToken;
        if (!token) return res.status(401).json({ message: 'No refresh token' });

        const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(payload.id);
        if (!user || user.refreshToken !== token)
            return res.status(403).json({ message: 'Refresh token invalid' });

        const accessToken = createAccessToken({ id: user._id, email: user.email });
        res.json({ accessToken });
    } catch (err) {
        res.status(401).json({ message: 'Refresh failed' });
    }
});

// LOGOUT
router.post('/logout', async (req, res) => {
    try {
        const token = req.cookies?.refreshToken;
        if (token) {
            const user = await User.findOne({ refreshToken: token });
            if (user) {
                user.refreshToken = null;
                await user.save();
            }
        }
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: isProd,
            sameSite: 'strict',
            path: '/api/auth/refresh',
        });
        res.json({ message: 'Logged out' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
