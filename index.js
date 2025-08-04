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
        // Log a message to ensure the transporter is being created
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
// The webhook endpoint must be defined BEFORE the global `express.json()` middleware
// to ensure the raw body is available for signature verification.
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const stripe = getStripe();
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    let event;
    let session; // Declare session variable outside try/catch
    let customer;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log('Webhook received:', event.type);
    } catch (err) {
        console.error(`Webhook signature verification failed:`, err.message);
        return res.sendStatus(400);
    }

    // Handle the event
    if (event.type === 'checkout.session.completed') {
        const checkoutSession = event.data.object;
        
        try {
            // FIX: Retrieve the full session object with line items and customer expanded
            session = await stripe.checkout.sessions.retrieve(checkoutSession.id, {
                expand: ['line_items', 'customer'],
            });
            customer = session.customer;

            console.log('Checkout Session completed:', session.id);

            // First, save the order to the database
            const db = getDbPool();
            const result = await db.query(
                'INSERT INTO orders (order_id, amount_total, customer_email, line_items) VALUES ($1, $2, $3, $4) RETURNING *',
                // FIX: Use customer.email to ensure the email is not null
                [session.id, session.amount_total / 100, customer.email, JSON.stringify(session.line_items.data)]
            );
            console.log('Order saved to database:', result.rows[0].order_id);

            // Now, handle email sending with specific error logging
            const transporter = getTransporter();

            // Create a formatted list of line items for the email
            const lineItemsHtml = session.line_items.data.map(item => 
                `<li>${item.quantity} x ${item.description} - $${(item.amount_total / 100).toFixed(2)}</li>`
            ).join('');
            
            // FIX: Use customer.email and customer.name for the customer email options
            const customerMailOptions = {
                from: emailUser,
                to: customer.email,
                subject: 'Order Confirmation from Nobilis Crochet',
                html: `
                    <h1>Thank You for Your Order!</h1>
                    <p>Hi ${customer.name || 'Customer'},</p>
                    <p>Your order #${session.id.slice(-8)} has been confirmed. We'll send you another email when it ships.</p>
                    <p><strong>Order Summary:</strong></p>
                    <ul>${lineItemsHtml}</ul>
                    <p>Total: $${(session.amount_total / 100).toFixed(2)}</p>
                    <p>If you have any questions, please contact us.</p>
                    <p>The Nobilis Crochet Team</p>
                `,
            };

            const ownerMailOptions = {
                from: emailUser,
                to: emailRecipient,
                subject: 'New Order Received',
                html: `<p>A new order has been placed. Order ID: ${session.id}</p><p>Customer email: ${customer.email}</p>`,
            };

            try {
                await transporter.sendMail(customerMailOptions);
                console.log('Confirmation email sent to customer.');
            } catch (emailError) {
                console.error('Error sending confirmation email to customer:', emailError);
            }

            try {
                await transporter.sendMail(ownerMailOptions);
                console.log('Order notification email sent to owner.');
            } catch (emailError) {
                console.error('Error sending order notification email to owner:', emailError);
            }

        } catch (error) {
            console.error('Error processing webhook event (database/email):', error);
        }
    }
    
    res.sendStatus(200);
});

// This global middleware should come AFTER the webhook route
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
            cancel_url: `${frontendUrl}/cancel.html`,
            
            // NEW: Enforce shipping address collection
            shipping_address_collection: {
                // You can add more countries here as needed
                // For example: allowed_countries: ['US', 'CA', 'GB']
                allowed_countries: ['US'],
            },
        });
        res.json({ url: session.url });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// A route to get order details for the account page.
app.get('/order-details', async (req, res) => {
    const stripe = getStripe();
    try {
        const { session_id } = req.query;
        if (!session_id) {
            return res.status(400).json({ error: 'Session ID is required.' });
        }
        
        const session = await stripe.checkout.sessions.retrieve(session_id, {
            expand: ['line_items'],
        });

        // The data for shipping address is in the session object.
        const shippingDetails = session.shipping_details;

        // The line items from Stripe contain a `price` object, which has `product.metadata`
        // We'll extract and format this as needed.
        const formattedLineItems = session.line_items.data.map(item => ({
            description: item.description,
            quantity: item.quantity,
            amount_total: item.amount_total / 100,
            // Check if metadata exists before accessing it
            metadata: item.price.product.metadata ? item.price.product.metadata : {},
        }));
        
        res.json({
            id: session.id,
            amount_total: session.amount_total / 100,
            amount_subtotal: session.amount_subtotal / 100,
            currency: session.currency,
            shipping_details: shippingDetails,
            shipping_cost: session.shipping_cost,
            total_details: session.total_details,
            line_items: formattedLineItems,
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
