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
// Use `express.json()` before the webhook handler so the raw body is available there.
app.use(express.json());
app.use(cors({ origin: frontendUrl, credentials: true }));
app.use(session({
    store: new PgSession({ pool: getDbPool(), tableName: 'sessions' }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- AUTHENTICATION ---
passport.use(new GoogleStrategy({
    clientID: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: `${serverUrl}/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const db = getDbPool();
        const user = {
            id: profile.id,
            display_name: profile.displayName,
            email: profile.emails[0].value,
        };
        // Check if user exists
        let result = await db.query('SELECT * FROM users WHERE id = $1', [user.id]);
        if (result.rows.length === 0) {
            // New user, insert into database
            await db.query('INSERT INTO users (id, display_name, email) VALUES ($1, $2, $3)',
                [user.id, user.display_name, user.email]);
        }
        done(null, user);
    } catch (error) {
        done(error);
    }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const db = getDbPool();
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (error) {
        done(error);
    }
});
const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { return next(); }
    res.status(401).json({ message: 'Authentication required' });
};

// --- ROUTES ---

// GET user info
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ user: req.user });
    } else {
        res.status(401).json({ user: null });
    }
});

// GET all reviews for a product
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


// --- STRIPE ROUTES ---

// THIS IS THE ROUTE THAT WAS MISSING
app.post('/create-checkout-session', async (req, res) => {
    const stripe = getStripe();
    const { cart } = req.body;
    
    // Convert cart items to Stripe line item format
    const lineItems = cart.map(item => ({
        price_data: {
            currency: 'usd',
            product_data: {
                name: item.name,
                images: [item.image]
            },
            // FIX: Convert item.price from a string to a number before calculating the unit_amount
            unit_amount: Math.round(parseFloat(item.price.replace('$', '')) * 100), // Stripe expects cents
        },
        quantity: item.quantity,
    }));

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            success_url: `${frontendUrl}/receipt.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontendUrl}/cart.html`,
        });
        res.json({ url: session.url });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// A route to get order details for the account page.
app.get('/order-details', async (req, res) => {
    // Note: This route is for getting order history, not creating a session
    const stripe = getStripe();
    try {
        const { session_id } = req.query;
        if (!session_id) {
            return res.status(400).json({ error: 'Session ID is required.' });
        }
        
        const session = await stripe.checkout.sessions.retrieve(session_id, {
            expand: ['line_items'],
        });

        res.json({
            id: session.id,
            amount_total: session.amount_total / 100,
            currency: session.currency,
            line_items: session.line_items.data.map(item => ({
                description: item.description,
                quantity: item.quantity,
                amount_total: item.amount_total / 100,
            })),
        });
    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).json({ error: 'Failed to fetch order details.' });
    }
});


// --- WEBHOOK ENDPOINT ---
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const stripe = getStripe();
    const payload = req.body;
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;

    try {
        event = stripe.webhooks.constructEvent(payload, sig, webhookSecret);
    } catch (err) {
        console.error(`Webhook signature verification failed:`, err.message);
        return res.sendStatus(400);
    }

    // Handle the event
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('Checkout Session completed:', session.id);

        try {
            // Here you would save the order to your database
            const db = getDbPool();
            const result = await db.query(
                'INSERT INTO orders (order_id, amount_total, customer_email, line_items) VALUES ($1, $2, $3, $4) RETURNING *',
                [session.id, session.amount_total / 100, session.customer_email, JSON.stringify(session.line_items.data)]
            );
            console.log('Order saved to database:', result.rows[0].order_id);

            // You can also send a confirmation email here
            const transporter = getTransporter();
            const mailOptions = {
                from: emailUser,
                to: emailRecipient, // Send to yourself
                subject: 'New Order Received',
                html: `<p>A new order has been placed. Order ID: ${session.id}</p><p>Customer email: ${session.customer_email}</p>`,
            };
            await transporter.sendMail(mailOptions);

        } catch (error) {
            console.error('Error processing webhook event:', error);
        }
    }
    
    res.sendStatus(200);
});

// --- SERVER LISTENER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
