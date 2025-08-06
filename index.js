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
        console.log("Attempting to create email transporter...");
        transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: emailUser, pass: emailPass }
        });
        console.log("Email transporter created.");
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
    const stripe = getStripe();
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.error(`Webhook signature verification failed:`, err.message);
        return res.sendStatus(400);
    }

    if (event.type === 'checkout.session.completed') {
        const checkoutSession = event.data.object;
        try {
            const session = await stripe.checkout.sessions.retrieve(checkoutSession.id, {
                expand: ['line_items.data.price.product', 'customer'],
            });
            const customer = session.customer ? session.customer : { email: checkoutSession.customer_details.email, name: checkoutSession.customer_details.name || 'Customer' };
            const db = getDbPool();

            // NEW: Calculate the total number of items to set the review credits
            const totalItems = session.line_items.data.reduce((sum, item) => sum + item.quantity, 0);

            await db.query(
                'INSERT INTO orders (order_id, amount_total, customer_email, line_items, review_uses_remaining) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                [session.id, session.amount_total / 100, customer.email, JSON.stringify(session.line_items.data), totalItems]
            );
            
            const transporter = getTransporter();
            const lineItemsHtml = session.line_items.data.map(item => `<li>${item.quantity} x ${item.description} - $${(item.amount_total / 100).toFixed(2)}</li>`).join('');
            const customerMailOptions = {
                from: emailUser,
                to: customer.email,
                subject: 'Order Confirmation from Nobilis Crochet',
                html: `<h1>Thank You for Your Order!</h1><p>Hi ${customer.name || 'Customer'},</p><p>Your order #${session.id.slice(-8)} has been confirmed.</p><p><strong>Order Summary:</strong></p><ul>${lineItemsHtml}</ul><p>Total: $${(session.amount_total / 100).toFixed(2)}</p>`,
            };
            const ownerMailOptions = {
                from: emailUser,
                to: emailRecipient,
                subject: `NEW ORDER #${session.id.slice(-8)} from ${customer.name || 'Customer'}`,
                html: `<h1>New Order Received!</h1><p><b>Order ID:</b> ${session.id}</p><p><b>Customer Email:</b> ${customer.email || 'N/A'}</p><hr><h3>Order Details:</h3><ul>${lineItemsHtml}</ul><p><b>Total:</b> $${(session.amount_total / 100).toFixed(2)}</p>`,
            };
            await transporter.sendMail(customerMailOptions);
            await transporter.sendMail(ownerMailOptions);
        } catch (error) {
            console.error('Error processing webhook event:', error);
        }
    }
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

// UPDATED: Review verification route with new logic
app.post('/api/verify-order-for-review', ensureAuthenticated, async (req, res) => {
    const { orderId, productId } = req.body;
    const { email: userEmail, google_id: userId } = req.user;
    const db = getDbPool();
    try {
        const orderResult = await db.query('SELECT * FROM orders WHERE order_id = $1', [orderId]);
        if (orderResult.rows.length === 0) {
            return res.status(404).json({ verified: false, message: 'Order not found.' });
        }
        const order = orderResult.rows[0];
        if (order.customer_email !== userEmail) {
            return res.status(403).json({ verified: false, message: 'This order does not belong to you.' });
        }
        if (order.review_uses_remaining <= 0) {
            return res.status(400).json({ verified: false, message: 'All reviews for this order have been used.' });
        }
        const reviewResult = await db.query('SELECT * FROM reviews WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        if (reviewResult.rows.length > 0) {
            return res.status(400).json({ verified: false, message: 'You have already reviewed this product.' });
        }
        res.json({ verified: true });
    } catch (error) {
        console.error('Error verifying order for review:', error);
        res.status(500).json({ verified: false, message: 'An internal error occurred.' });
    }
});

// UPDATED: Review submission route with new logic
app.post('/api/reviews', ensureAuthenticated, async (req, res) => {
    const { orderId, productId, rating, comment } = req.body;
    const { email: userEmail, google_id: userId, display_name: userName } = req.user;
    const db = getDbPool();
    const client = await db.connect(); // Get a client from the pool for a transaction

    try {
        // --- Start Transaction ---
        await client.query('BEGIN');

        // 1. Verify the order again inside the transaction to prevent race conditions
        const orderResult = await client.query('SELECT * FROM orders WHERE order_id = $1 FOR UPDATE', [orderId]); // Lock the row
        if (orderResult.rows.length === 0) throw new Error('Order not found.');
        const order = orderResult.rows[0];
        if (order.customer_email !== userEmail) throw new Error('This order does not belong to you.');
        if (order.review_uses_remaining <= 0) throw new Error('All reviews for this order have been used.');
        
        // 2. Check if the user has already reviewed this product
        const reviewResult = await client.query('SELECT * FROM reviews WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        if (reviewResult.rows.length > 0) throw new Error('You have already reviewed this product.');

        // 3. Insert the new review
        const insertReviewResult = await client.query(
            'INSERT INTO reviews (product_id, user_id, user_name, rating, comment, order_id_used) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [productId, userId, userName, rating, comment, orderId]
        );

        // 4. Decrement the review uses for the order
        await client.query(
            'UPDATE orders SET review_uses_remaining = review_uses_remaining - 1 WHERE order_id = $1',
            [orderId]
        );

        // --- Commit Transaction ---
        await client.query('COMMIT');
        res.status(201).json(insertReviewResult.rows[0]);

    } catch (error) {
        // --- Rollback Transaction on Error ---
        await client.query('ROLLBACK');
        console.error('Error posting review:', error);
        res.status(500).json({ error: error.message || 'Failed to post review' });
    } finally {
        // --- Release Client ---
        client.release();
    }
});

app.post('/create-checkout-session', async (req, res) => {
    const stripe = getStripe();
    const { cart } = req.body;
    const lineItems = cart.map(item => ({
        price_data: {
            currency: 'usd',
            product_data: {
                name: item.name,
                images: item.image ? [item.image] : (item.images ? [item.images.head] : undefined),
                metadata: { productId: item.id }
            },
            unit_amount: Math.round(parseFloat(item.price.replace('$', '')) * 100),
        },
        quantity: item.quantity,
    }));
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            success_url: `${frontendUrl}/receipt.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontendUrl}/cancel.html`,
            shipping_address_collection: { allowed_countries: ['US'] },
        });
        res.json({ url: session.url });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

app.get('/order-details', async (req, res) => {
    const stripe = getStripe();
    try {
        const { session_id } = req.query;
        if (!session_id) {
            return res.status(400).json({ error: 'Session ID is required.' });
        }
        const session = await stripe.checkout.sessions.retrieve(session_id, {
            expand: ['line_items.data.price.product'],
        });
        res.json({
            id: session.id,
            amount_total: session.amount_total / 100,
            shipping_details: session.shipping_details,
            line_items: session.line_items.data,
        });
    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).json({ error: 'Failed to fetch order details.' });
    }
});

// --- SERVER LISTENER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));
