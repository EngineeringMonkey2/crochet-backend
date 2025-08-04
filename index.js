// index.js

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
app.use(cors({
    origin: frontendUrl,
    credentials: true
}));
app.use(express.json());
app.use(session({
    store: new PgSession({ pool: getDbPool(), createTableIfMissing: true }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, httpOnly: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- PASSPORT (GOOGLE OAUTH) CONFIGURATION ---
passport.use(new GoogleStrategy({
    clientID: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: `${serverUrl}/auth/google/callback`,
    scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    const { id, displayName, emails } = profile;
    const email = emails[0].value;
    const db = getDbPool();
    try {
        let userResult = await db.query('SELECT * FROM users WHERE google_id = $1', [id]);
        if (userResult.rows.length > 0) {
            return done(null, userResult.rows[0]);
        } else {
            let newUserResult = await db.query(
                'INSERT INTO users (google_id, display_name, email) VALUES ($1, $2, $3) RETURNING *',
                [id, displayName, email]
            );
            return done(null, newUserResult.rows[0]);
        }
    } catch (err) {
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    const db = getDbPool();
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (err) {
        done(err, null);
    }
});

// --- AUTHENTICATION ROUTES ---
app.get('/auth/google', passport.authenticate('google'));
app.get('/auth/google/callback',
    passport.authenticate('google', {
        successRedirect: `${frontendUrl}/account.html`,
        failureRedirect: `${frontendUrl}/login.html`
    })
);
app.get('/auth/logout', (req, res, next) => {
    req.logout(err => {
        if (err) { return next(err); }
        req.session.destroy(() => {
            res.clearCookie('connect.sid');
            res.redirect(`${frontendUrl}/index.html`);
        });
    });
});

// --- MIDDLEWARE TO PROTECT ROUTES ---
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.status(401).json({ error: 'User not authenticated' });
}

// --- API ROUTES ---
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ user: req.user });
    } else {
        res.status(401).json({ user: null });
    }
});

app.get('/api/orders', ensureAuthenticated, async (req, res) => {
    try {
        const db = getDbPool();
        // This query now works because the `user_id` column will exist
        const result = await db.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.get('/api/reviews/:productId', async (req, res) => {
    const { productId } = req.params;
    try {
        const db = getDbPool();
        const result = await db.query('SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC', [productId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).json({ error: 'Failed to fetch reviews' });
    }
});

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
app.post('/api/create-checkout-session', ensureAuthenticated, async (req, res) => {
    try {
        const { cart } = req.body;
        const stripe = getStripe();

        const line_items = cart.map(item => {
            const priceInCents = Math.round(parseFloat(item.price.replace('$', '')) * 100);
            return {
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: item.name,
                        images: item.images.hasOwnProperty('head') ? [Object.values(item.images)[0]] : [item.images[0]],
                    },
                    unit_amount: priceInCents,
                },
                quantity: item.quantity,
            };
        });

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: line_items,
            mode: 'payment',
            success_url: `${frontendUrl}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontendUrl}/cart.html`,
            // Pass the internal user ID to the webhook
            metadata: {
                userId: req.user.id 
            },
            // Collect customer email on the Stripe page
            customer_email: req.user.email
        });
        res.json({ url: session.url });
    } catch (error) {
        console.error("Error creating Stripe session:", error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

app.get('/api/order-details', async (req, res) => {
    const sessionId = req.query.session_id;
    try {
        const stripe = getStripe();
        const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
        res.json(session);
    } catch (error) {
        console.error("Error fetching order details:", error);
        res.status(500).json({ error: 'Failed to fetch order details' });
    }
});

// This route should remain at the root as Stripe calls it directly
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const stripe = getStripe();
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.error(`Webhook signature verification failed.`, err.message);
        return res.sendStatus(400);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        
        try {
            const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
            const db = getDbPool();
            
            // UPDATED: This query now matches your 'orders' table schema exactly.
            const queryText = `
                INSERT INTO orders (
                    order_id, 
                    user_id, 
                    customer_email, 
                    amount_total, 
                    shipping_details, 
                    line_items, 
                    status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            `;
            
            const values = [
                session.id,
                session.metadata.userId, // The user ID from your database
                session.customer_details.email,
                session.amount_total / 100, // Convert from cents to dollars
                JSON.stringify(session.shipping_details),
                JSON.stringify(lineItems.data),
                session.payment_status
            ];

            await db.query(queryText, values);
            
        } catch (dbError) {
            console.error('Error saving order to database:', dbError);
        }
    }
    res.json({ received: true });
});


// --- SERVER START ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
