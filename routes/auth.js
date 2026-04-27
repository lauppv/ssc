const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const db = require('../db/database');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

function generateAccessToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );
}

function generateRefreshToken(userId) {
    const token = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(userId, token, expiresAt);

    return token;
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Email, password, and name are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
        if (existing) {
            return res.status(409).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const result = db.prepare(
            'INSERT INTO users (email, password, name, role, provider) VALUES (?, ?, ?, ?, ?)'
        ).run(email, hashedPassword, name, 'user', 'local');

        const user = { id: result.lastInsertRowid, email, role: 'user' };
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user.id);

        res.status(201).json({
            message: 'User registered successfully',
            user: { id: user.id, email, name, role: 'user' },
            accessToken,
            refreshToken
        });
    } catch (err) {
        res.status(500).json({ error: 'Registration failed', details: err.message });
    }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = db.prepare('SELECT * FROM users WHERE email = ? AND provider = ?').get(email, 'local');
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user.id);

        res.json({
            message: 'Login successful',
            user: { id: user.id, email: user.email, name: user.name, role: user.role },
            accessToken,
            refreshToken
        });
    } catch (err) {
        res.status(500).json({ error: 'Login failed', details: err.message });
    }
});

// POST /api/auth/refresh — Refresh Token Rotation
router.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' });
    }

    const stored = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refreshToken);
    if (!stored) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }

    if (new Date(stored.expires_at) < new Date()) {
        db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(stored.id);
        return res.status(401).json({ error: 'Refresh token expired' });
    }

    // Rotation: delete old token, issue new pair
    db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(stored.id);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(stored.user_id);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user.id);

    res.json({
        message: 'Tokens refreshed (old refresh token invalidated)',
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
    });
});

// POST /api/auth/google — Google OAuth 2.0 login
router.post('/google', async (req, res) => {
    try {
        const { idToken } = req.body;

        if (!idToken) {
            return res.status(400).json({ error: 'Google ID token required' });
        }

        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();

        let user = db.prepare('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('google', payload.sub);

        if (!user) {
            const result = db.prepare(
                'INSERT INTO users (email, name, role, provider, provider_id) VALUES (?, ?, ?, ?, ?)'
            ).run(payload.email, payload.name, 'user', 'google', payload.sub);

            user = { id: result.lastInsertRowid, email: payload.email, role: 'user', name: payload.name };
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user.id);

        res.json({
            message: 'Google OAuth login successful',
            user: { id: user.id, email: user.email, name: user.name, role: user.role },
            accessToken,
            refreshToken
        });
    } catch (err) {
        res.status(401).json({ error: 'Google authentication failed', details: err.message });
    }
});

// POST /api/auth/logout — Invalidate refresh token
router.post('/logout', (req, res) => {
    const { refreshToken } = req.body;

    if (refreshToken) {
        db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken);
    }

    res.json({ message: 'Logged out successfully' });
});

// GET /api/auth/me — Get current user info
router.get('/me', authenticate, (req, res) => {
    const user = db.prepare('SELECT id, email, name, role, provider, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
});

module.exports = router;
