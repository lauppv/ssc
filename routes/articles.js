const express = require('express');
const db = require('../db/database');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// GET /api/articles — Public: anyone can read articles
router.get('/', (req, res) => {
    const articles = db.prepare(`
        SELECT articles.*, users.name as author_name
        FROM articles
        JOIN users ON articles.author_id = users.id
        ORDER BY articles.created_at DESC
    `).all();
    res.json({ articles });
});

// GET /api/articles/:id — Public
router.get('/:id', (req, res) => {
    const article = db.prepare(`
        SELECT articles.*, users.name as author_name
        FROM articles
        JOIN users ON articles.author_id = users.id
        WHERE articles.id = ?
    `).get(req.params.id);

    if (!article) {
        return res.status(404).json({ error: 'Article not found' });
    }
    res.json({ article });
});

// POST /api/articles — Authenticated: any logged-in user can create
router.post('/', authenticate, (req, res) => {
    const { title, content } = req.body;

    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }

    const result = db.prepare(
        'INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)'
    ).run(title, content, req.user.id);

    const article = db.prepare('SELECT * FROM articles WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ message: 'Article created', article });
});

// PUT /api/articles/:id — Authenticated: only author or admin can edit
router.put('/:id', authenticate, (req, res) => {
    const article = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);

    if (!article) {
        return res.status(404).json({ error: 'Article not found' });
    }

    if (article.author_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'You can only edit your own articles' });
    }

    const { title, content } = req.body;
    db.prepare('UPDATE articles SET title = COALESCE(?, title), content = COALESCE(?, content) WHERE id = ?')
        .run(title || null, content || null, req.params.id);

    const updated = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);
    res.json({ message: 'Article updated', article: updated });
});

// DELETE /api/articles/:id — Admin only
router.delete('/:id', authenticate, authorize('admin'), (req, res) => {
    const article = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);

    if (!article) {
        return res.status(404).json({ error: 'Article not found' });
    }

    db.prepare('DELETE FROM articles WHERE id = ?').run(req.params.id);
    res.json({ message: 'Article deleted' });
});

// GET /api/articles/admin/all — Admin only: see all articles with user details
router.get('/admin/all', authenticate, authorize('admin'), (req, res) => {
    const articles = db.prepare(`
        SELECT articles.*, users.name as author_name, users.email as author_email
        FROM articles
        JOIN users ON articles.author_id = users.id
        ORDER BY articles.created_at DESC
    `).all();
    res.json({ articles });
});

module.exports = router;
