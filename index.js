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

            const customer = session.customer ? session.customer : { 
                email: checkoutSession.customer_details.email, 
                name: checkoutSession.customer_details.name || 'Customer' 
            };
            
            console.log('Checkout Session completed:', session.id);

            const db = getDbPool();
            const result = await db.query(
                'INSERT INTO orders (order_id, amount_total, customer_email, line_items) VALUES ($1, $2, $3, $4) RETURNING *',
                [session.id, session.amount_total / 100, customer.email, JSON.stringify(session.line_items.data)]
            );
            console.log('Order saved to database:', result.rows[0].order_id);

            // Email logic can be added here if needed

        } catch (error) {
            console.error('Error processing webhook event (database/email):', error);
        }
    }

    res.sendStatus(200);
});

app.use(express.json());
// IMPORTANT: Trust the proxy to handle secure cookies correctly
app.set('trust proxy', 1); 
app.use(cors({ origin: frontendUrl, credentials: true }));

// UPDATED: Session middleware with correct cookie settings for cross-domain auth
app.use(session({
    store: new PgSession({ pool: getDbPool(), tableName: 'sessions' }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, // Must be true since we are setting sameSite='none'
        sameSite: 'none', // Allow cookie to be sent from frontend domain to backend domain
        httpOnly: true, // Helps prevent XSS attacks
        maxAge: 24 * 60 * 60 * 1000 // 24-hour session
    }
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
        const googleId = profile.id;
        const displayName = profile.displayName;
        const email = profile.emails[0].value;

        let result = await db.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
        let user;
        if (result.rows.length === 0) {
            const insertResult = await db.query(
                'INSERT INTO users (google_id, display_name, email) VALUES ($1, $2, $3) RETURNING *',
                [googleId, displayName, email]
            );
            user = insertResult.rows[0];
        } else {
            user = result.rows[0];
        }
        done(null, user);
    } catch (error) {
        done(error);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const db = getDbPool();
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        if (result.rows.length > 0) {
            done(null, result.rows[0]);
        } else {
            done(new Error('User not found'));
        }
    } catch (error) {
        done(error);
    }
});

const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { return next(); }
    res.status(401).json({ message: 'Authentication required' });
};

// --- AUTH ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: `${frontendUrl}/login.html?error=true`,
    successRedirect: `${frontendUrl}/account.html`,
}));

app.post('/auth/logout', (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect(`${frontendUrl}/`);
    });
});


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
        const result = await db.query('SELECT * FROM orders WHERE customer_email = $1 ORDER BY created_at DESC', [req.user.email]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

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

app.post('/api/reviews', ensureAuthenticated, async (req, res) => {
    try {
        const { productId, rating, comment } = req.body;
        const userId = req.user.google_id;
        const userName = req.user.display_name;

        const db = getDbPool();
        const result = await db.query(
            'INSERT INTO reviews (product_id, user_id, user_name, rating, comment) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (product_id, user_id) DO UPDATE SET rating = EXCLUDED.rating, comment = EXCLUDED.comment, created_at = NOW() RETURNING *',
            [productId, userId, userName, rating, comment]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error posting review:', error);
        res.status(500).json({ error: 'Failed to post review' });
    }
});

app.get('/api/user/has-purchased/:productId', ensureAuthenticated, async (req, res) => {
    try {
        const { productId } = req.params;
        const userEmail = req.user.email;
        const db = getDbPool();

        const ordersResult = await db.query('SELECT line_items FROM orders WHERE customer_email = $1', [userEmail]);

        if (ordersResult.rows.length === 0) {
            return res.json({ hasPurchased: false });
        }

        let hasPurchased = false;
        for (const order of ordersResult.rows) {
            const lineItems = order.line_items; 
            if (lineItems && Array.isArray(lineItems)) {
                for (const item of lineItems) {
                    if (String(item.price?.product?.metadata?.productId) === String(productId)) {
                        hasPurchased = true;
                        break;
                    }
                }
            }
            if (hasPurchased) break;
        }

        res.json({ hasPurchased });
    } catch (error) {
        console.error('Error checking purchase history:', error);
        res.status(500).json({ error: 'Failed to check purchase history' });
    }
});


// --- STRIPE ROUTES ---
app.post('/create-checkout-session', async (req, res) => {
    const stripe = getStripe();
    const { cart } = req.body;

    const lineItems = cart.map(item => {
        const productData = {
            name: item.name,
            images: item.image ? [item.image] : undefined,
            metadata: {
                productId: item.id 
            }
        };

        if (item.name === 'Custom Monkey' && item.images) {
            const shortImages = {};
            for (const part in item.images) {
                shortImages[part] = item.images[part].split('/').pop();
            }
            productData.metadata.custom_details = JSON.stringify(shortImages);
        }

        return {
            price_data: {
                currency: 'usd',
                product_data: productData,
                unit_amount: Math.round(parseFloat(item.price.replace('$', '')) * 100),
            },
            quantity: item.quantity,
        };
    });

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            success_url: `${frontendUrl}/receipt.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontendUrl}/cancel.html`,
            shipping_address_collection: {
                allowed_countries: ['US'],
            },
        });
        res.json({ url: session.url });
    } catch (error) {
        console.error('Error creating checkout session:', error);
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
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
