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
const emailRecipient = process.env.EMAIL_RECIPIENT;
const databaseUrl = process.env.DATABASE_URL;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const serverUrl = process.env.RENDER_EXTERNAL_URL;
const frontendUrl = process.env.FRONTEND_URL || 'https://nobiliscrochet.com';

// --- LAZY INITIALIZATION & DB POOL ---
let stripeInstance, transporter, dbPool;
function getStripe() { if (!stripeInstance) { stripeInstance = stripe(stripeSecretKey); } return stripeInstance; }
function getTransporter() { if (!transporter) { transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: emailUser, pass: emailPass } }); } return transporter; }
function getDbPool() { if (!dbPool) { dbPool = new Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: false } }); } return dbPool; }

// --- MIDDLEWARE ---
const allowedOrigins = [frontendUrl, 'http://localhost:5500']; // Add your local dev URL if needed
app.use(cors({ origin: allowedOrigins, credentials: true }));

app.use((req, res, next) => {
    if (req.originalUrl.includes('/stripe-webhook')) { next(); } 
    else { express.json()(req, res, next); }
});

// --- SESSION & AUTHENTICATION SETUP ---
app.use(session({
    store: new PgSession({ pool: getDbPool(), createTableIfMissing: true }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true, 
        httpOnly: true, 
        sameSite: 'none',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
    try {
        const result = await getDbPool().query('SELECT id, google_id, email, display_name FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (err) {
        done(err, null);
    }
});

passport.use(new GoogleStrategy({
    clientID: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: `${serverUrl}/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
        const db = getDbPool();
        const email = profile.emails[0].value;
        let result = await db.query('SELECT * FROM users WHERE google_id = $1 OR email = $2', [profile.id, email]);
        let user = result.rows[0];

        if (!user) {
            result = await db.query(
                'INSERT INTO users (google_id, email, display_name) VALUES ($1, $2, $3) RETURNING *',
                [profile.id, email, profile.displayName]
            );
            user = result.rows[0];
        }
        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
  }
));

// --- AUTHENTICATION ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: `${frontendUrl}/login.html?error=auth_failed` }),
  (req, res) => res.redirect(`${frontendUrl}/account.html`)
);

app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ user: req.user });
    } else {
        res.status(401).json({ user: null });
    }
});

app.post('/auth/logout', (req, res, next) => {
    req.logout(err => {
        if (err) { return next(err); }
        req.session.destroy(() => {
            res.clearCookie('connect.sid');
            res.status(200).send({ message: 'Logged out successfully' });
        });
    });
});

// --- NEW API ROUTES FOR DATA ---

// Middleware to protect routes
const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ error: 'User not authenticated' });
};

// Get order history for the logged-in user
app.get('/api/orders', ensureAuthenticated, async (req, res) => {
    try {
        const db = getDbPool();
        const result = await db.query('SELECT * FROM orders WHERE customer_email = $1 ORDER BY created_at DESC', [req.user.email]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// Get reviews for a specific product
app.get('/api/reviews/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        const db = getDbPool();
        const result = await db.query('SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC', [productId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).json({ error: 'Failed to fetch reviews' });
    }
});

// Post a new review
app.post('/api/reviews', ensureAuthenticated, async (req, res) => {
    try {
        const { productId, rating, comment } = req.body;
        const { id: userId, display_name: userName } = req.user;
        
        const db = getDbPool();
        const result = await db.query(
            'INSERT INTO reviews (product_id, user_id, user_name, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [productId, userId, userName, rating, comment]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error posting review:', error);
        res.status(500).json({ error: 'Failed to post review' });
    }
});


// --- EXISTING STRIPE ROUTES ---
app.post('/create-checkout-session', async (req, res) => { /* ... unchanged ... */ });
app.get('/order-details', async (req, res) => { /* ... unchanged ... */ });
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => { /* ... unchanged ... */ });

// --- START THE SERVER ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
