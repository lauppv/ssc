const express = require('express');
const db = require('../db/database');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// GET /api/admin/users — List all users
router.get('/users', authenticate, authorize('admin'), (req, res) => {
    const users = db.prepare('SELECT id, email, name, role, provider, created_at FROM users').all();
    res.json({ users });
});

// PATCH /api/admin/users/:id/role — Change user role
router.patch('/users/:id/role', authenticate, authorize('admin'), (req, res) => {
    const { role } = req.body;

    if (!role || !['user', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Role must be "user" or "admin"' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    if (user.id === req.user.id) {
        return res.status(400).json({ error: 'Cannot change your own role' });
    }

    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);

    res.json({
        message: `User role updated to "${role}"`,
        user: { id: user.id, email: user.email, name: user.name, role }
    });
});

// DELETE /api/admin/users/:id — Delete a user
router.delete('/users/:id', authenticate, authorize('admin'), (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    if (user.id === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete yourself' });
    }

    db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(req.params.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);

    res.json({ message: 'User deleted', user: { id: user.id, email: user.email } });
});

module.exports = router;
