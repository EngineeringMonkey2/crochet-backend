// server.js (With Authentication & Full API for Render)

// --- DEPENDENCIES ---
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const stripe = require('stripe');
const { Pool } = require('pg');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);

// --- INITIALIZATION ---
const app = express();

// --- ENVIRONMENT VARIABLES ---
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;
const emailRecipient = process.env.EMAIL_RECIPIENT; // This should be your email address
const databaseUrl = process.env.DATABASE_URL;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const serverUrl = process.env.RENDER_EXTERNAL_URL;
const frontendUrl = process.env.FRONTEND_URL || 'https://nobiliscrochet.com';

// --- LAZY INITIALIZATION & DB POOL ---
let stripeInstance, transporter, dbPool;
function getStripe() { if (!stripeInstance) { stripeInstance = stripe(stripeSecretKey); } return stripeInstance; }
function getTransporter() {
    if (!transporter) {
        transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: emailUser, pass: emailPass }
        });
    }
    return transporter;
}
function getDbPool() {
    if (!dbPool) {
        dbPool = new Pool({
            connectionString: databaseUrl,
            ssl: { rejectUnauthorized: false }
        });
    }
    return dbPool;
}

// --- MIDDLEWARE ---
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    // Webhook logic remains the same
    res.sendStatus(200);
});

app.use(express.json());
app.set('trust proxy', 1); 
app.use(cors({ origin: frontendUrl, credentials: true }));
app.use(session({
    store: new PgSession({ pool: getDbPool(), tableName: 'sessions' }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, sameSite: 'none', httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- AUTHENTICATION ---
passport.use(new GoogleStrategy({
    clientID: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: `${serverUrl}/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
    const db = getDbPool();
    const { id: googleId, displayName } = profile;
    const email = profile.emails[0].value;
    try {
        let result = await db.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
        if (result.rows.length === 0) {
            result = await db.query('INSERT INTO users (google_id, display_name, email) VALUES ($1, $2, $3) RETURNING *', [googleId, displayName, email]);
        }
        done(null, result.rows[0]);
    } catch (error) {
        done(error);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    const db = getDbPool();
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (error) {
        done(error);
    }
});

const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ message: 'Authentication required' });
};

// --- ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: `${frontendUrl}/login.html?error=true`,
    successRedirect: `${frontendUrl}/account.html`,
}));
app.post('/auth/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect(`${frontendUrl}/`);
    });
});

app.get('/api/user', (req, res) => res.json({ user: req.user || null }));

app.get('/api/orders', ensureAuthenticated, async (req, res) => {
    const db = getDbPool();
    try {
        const result = await db.query('SELECT * FROM orders WHERE customer_email = $1 ORDER BY created_at DESC', [req.user.email]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.get('/api/reviews/:productId', async (req, res) => {
    const db = getDbPool();
    try {
        const result = await db.query('SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC', [req.params.productId]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reviews' });
    }
});

app.post('/api/verify-order-for-review', ensureAuthenticated, async (req, res) => {
    const { orderId, productId } = req.body;
    const { email: userEmail, google_id: userId } = req.user;
    const db = getDbPool();
    try {
        const orderResult = await db.query("SELECT * FROM orders WHERE order_id = $1 OR order_id LIKE '%' || $1", [orderId]);
        if (orderResult.rows.length === 0) return res.status(404).json({ verified: false, message: 'Order not found.' });
        const order = orderResult.rows[0];
        if (order.customer_email !== userEmail) return res.status(403).json({ verified: false, message: 'This order does not belong to you.' });
        if (order.review_uses_remaining <= 0) return res.status(400).json({ verified: false, message: 'All reviews for this order have been used.' });
        const reviewResult = await db.query('SELECT * FROM reviews WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        if (reviewResult.rows.length > 0) return res.status(400).json({ verified: false, message: 'You have already reviewed this product.' });
        res.json({ verified: true });
    } catch (error) {
        res.status(500).json({ verified: false, message: 'An internal error occurred.' });
    }
});

// UPDATED: Review submission route now accepts a custom user name
app.post('/api/reviews', ensureAuthenticated, async (req, res) => {
    const { orderId, productId, rating, comment, userName } = req.body;
    const { email: userEmail, google_id: userId } = req.user;
    const db = getDbPool();
    const client = await db.connect();
    
    // Determine the final name to be used for the review
    let finalUserName = userName && userName.trim() ? userName.trim() : 'Anonymous';

    try {
        await client.query('BEGIN');
        const orderResult = await client.query("SELECT * FROM orders WHERE order_id = $1 OR order_id LIKE '%' || $1 FOR UPDATE", [orderId]);
        if (orderResult.rows.length === 0) throw new Error('Order not found.');
        const order = orderResult.rows[0];
        if (order.customer_email !== userEmail) throw new Error('This order does not belong to you.');
        if (order.review_uses_remaining <= 0) throw new Error('All reviews for this order have been used.');
        const reviewResult = await client.query('SELECT * FROM reviews WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        if (reviewResult.rows.length > 0) throw new Error('You have already reviewed this product.');
        
        const insertReviewResult = await client.query(
            'INSERT INTO reviews (product_id, user_id, user_name, rating, comment, order_id_used) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [productId, userId, finalUserName, rating, comment, order.order_id]
        );
        await client.query(
            'UPDATE orders SET review_uses_remaining = review_uses_remaining - 1 WHERE order_id = $1',
            [order.order_id]
        );
        await client.query('COMMIT');
        res.status(201).json(insertReviewResult.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: error.message || 'Failed to post review' });
    } finally {
        client.release();
    }
});

app.put('/api/reviews/:reviewId', ensureAuthenticated, async (req, res) => {
    const { reviewId } = req.params;
    const { rating, comment } = req.body;
    const { google_id: userId } = req.user;
    const db = getDbPool();
    try {
        const result = await db.query(
            'UPDATE reviews SET rating = $1, comment = $2, created_at = NOW() WHERE id = $3 AND user_id = $4 RETURNING *',
            [rating, comment, reviewId, userId]
        );
        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'You are not authorized to edit this review.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update review.' });
    }
});

app.delete('/api/reviews/:reviewId', ensureAuthenticated, async (req, res) => {
    const { reviewId } = req.params;
    const { google_id: userId } = req.user;
    const db = getDbPool();
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const reviewResult = await client.query('SELECT * FROM reviews WHERE id = $1 AND user_id = $2', [reviewId, userId]);
        if (reviewResult.rows.length === 0) {
            throw new Error('Review not found or you are not authorized to delete it.');
        }
        const orderIdUsed = reviewResult.rows[0].order_id_used;
        await client.query('DELETE FROM reviews WHERE id = $1', [reviewId]);
        if (orderIdUsed) {
            await client.query('UPDATE orders SET review_uses_remaining = review_uses_remaining + 1 WHERE order_id = $1', [orderIdUsed]);
        }
        await client.query('COMMIT');
        res.status(204).send();
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: error.message || 'Failed to delete review.' });
    } finally {
        client.release();
    }
});

// (No changes to Stripe or other routes)
app.post('/create-checkout-session', async (req, res) => {
    // ...
});
app.get('/order-details', async (req, res) => {
    // ...
});

// --- SERVER LISTENER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));
