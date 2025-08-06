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
        console.log('Webhook received:', event.type);
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
            
            const totalItems = session.line_items.data.reduce((sum, item) => sum + item.quantity, 0);

            await db.query(
                'INSERT INTO orders (order_id, amount_total, customer_email, line_items, review_uses_remaining) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                [session.id, session.amount_total / 100, customer.email, JSON.stringify(session.line_items.data), totalItems]
            );

            const transporter = getTransporter();
            const formatLineItem = (item) => {
                const metadata = item.price && item.price.product ? item.price.product.metadata : {};
                if (metadata.custom_details) {
                    const customDetails = JSON.parse(metadata.custom_details);
                    const customDetailsHtml = Object.entries(customDetails).map(([part, filename]) => `<li>${part}: ${filename}</li>`).join('');
                    return `<li><b>Item:</b> ${item.description} <br><b>Quantity:</b> ${item.quantity} <br><b>Price:</b> $${(item.amount_total / 100).toFixed(2)} <br><b>Custom Details:</b><ul>${customDetailsHtml}</ul></li>`;
                } else {
                    return `<li>${item.quantity} x ${item.description} - $${(item.amount_total / 100).toFixed(2)}</li>`;
                }
            };
            const lineItemsHtml = session.line_items.data.map(formatLineItem).join('');
            const customerMailOptions = {
                from: emailUser, to: customer.email, subject: 'Order Confirmation from Nobilis Crochet',
                html: `<h1>Thank You for Your Order!</h1><p>Hi ${customer.name || 'Customer'},</p><p>Your order #${session.id.slice(-8)} has been confirmed. We'll send you another email when it ships.</p><p><strong>Order Summary:</strong></p><ul>${lineItemsHtml}</ul><p>Total: $${(session.amount_total / 100).toFixed(2)}</p><p>If you have any questions, please contact us.</p><p>The Nobilis Crochet Team</p>`,
            };
            const ownerMailOptions = {
                from: emailUser, to: emailRecipient, subject: `NEW ORDER #${session.id.slice(-8)} from ${customer.name || 'Customer'}`,
                html: `<h1>New Order Received!</h1><p><b>Order ID:</b> ${session.id}</p><p><b>Customer Name:</b> ${customer.name || 'N/A'}</p><p><b>Customer Email:</b> ${customer.email || 'N/A'}</p><hr><h3>Order Details:</h3><ul>${lineItemsHtml}</ul><p><b>Total:</b> $${(session.amount_total / 100).toFixed(2)}</p><hr><h3>Shipping Address:</h3><p>${session.shipping_details ? session.shipping_details.name : 'N/A'}<br>${session.shipping_details ? (session.shipping_details.address.line1 || 'N/A') : ''}${session.shipping_details && session.shipping_details.address.line2 ? '<br>' + session.shipping_details.address.line2 : ''}<br>${session.shipping_details ? (session.shipping_details.address.city || 'N/A') : ''}, ${session.shipping_details ? (session.shipping_details.address.state || 'N/A') : ''} ${session.shipping_details ? (session.shipping_details.address.postal_code || 'N/A') : ''}<br>${session.shipping_details ? (session.shipping_details.address.country || 'N/A') : ''}</p>`,
            };
            await transporter.sendMail(customerMailOptions);
            await transporter.sendMail(ownerMailOptions);
        } catch (error) {
            console.error('Error processing webhook event (database/email):', error);
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

app.post('/api/verify-order-for-review', ensureAuthenticated, async (req, res) => {
    const { orderId, productId } = req.body;
    const { email: userEmail, google_id: userId } = req.user;
    const db = getDbPool();
    try {
        const orderResult = await db.query('SELECT * FROM orders WHERE order_id = $1', [orderId]);
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

app.post('/api/reviews', ensureAuthenticated, async (req, res) => {
    const { orderId, productId, rating, comment } = req.body;
    const { email: userEmail, google_id: userId, display_name: userName } = req.user;
    const db = getDbPool();
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const orderResult = await client.query('SELECT * FROM orders WHERE order_id = $1 FOR UPDATE', [orderId]);
        if (orderResult.rows.length === 0) throw new Error('Order not found.');
        const order = orderResult.rows[0];
        if (order.customer_email !== userEmail) throw new Error('This order does not belong to you.');
        if (order.review_uses_remaining <= 0) throw new Error('All reviews for this order have been used.');
        const reviewResult = await client.query('SELECT * FROM reviews WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        if (reviewResult.rows.length > 0) throw new Error('You have already reviewed this product.');
        const insertReviewResult = await client.query(
            'INSERT INTO reviews (product_id, user_id, user_name, rating, comment, order_id_used) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [productId, userId, userName, rating, comment, orderId]
        );
        await client.query('UPDATE orders SET review_uses_remaining = review_uses_remaining - 1 WHERE order_id = $1', [orderId]);
        await client.query('COMMIT');
        res.status(201).json(insertReviewResult.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: error.message || 'Failed to post review' });
    } finally {
        client.release();
    }
});

app.post('/create-checkout-session', async (req, res) => {
    const stripe = getStripe();
    const { cart } = req.body;
    const lineItems = cart.map(item => {
        const productData = { name: item.name, images: item.image ? [item.image] : undefined, metadata: { productId: item.id } };
        if (item.name === 'Custom Monkey' && item.images) {
            const shortImages = {};
            for (const part in item.images) { shortImages[part] = item.images[part].split('/').pop(); }
            productData.metadata.custom_details = JSON.stringify(shortImages);
        }
        return {
            price_data: { currency: 'usd', product_data: productData, unit_amount: Math.round(parseFloat(item.price.replace('$', '')) * 100) },
            quantity: item.quantity,
        };
    });
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'], line_items: lineItems, mode: 'payment',
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
        if (!session_id) return res.status(400).json({ error: 'Session ID is required.' });
        const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['line_items.data.price.product'] });
        res.json({
            id: session.id, amount_total: session.amount_total / 100, shipping_details: session.shipping_details,
            line_items: session.line_items.data,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch order details.' });
    }
});

// --- SERVER LISTENER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));
