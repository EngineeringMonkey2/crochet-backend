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

// FIX: CORS middleware is now configured and placed at the very top of the middleware stack
app.use(cors({ origin: frontendUrl, credentials: true }));
app.use(express.json()); // This is global for all other routes

// --- MIDDLEWARE ---
// The webhook endpoint must be defined BEFORE the global `express.json()` middleware
// to ensure the raw body is available for signature verification.
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const stripe = getStripe();
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    let event;
    let session;
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
            session = await stripe.checkout.sessions.retrieve(checkoutSession.id, {
                expand: ['line_items', 'customer'],
            });
            
            if (session.customer && typeof session.customer === 'object') {
                customer = session.customer;
            } else if (session.customer) {
                customer = await stripe.customers.retrieve(session.customer);
            } else {
                customer = { email: checkoutSession.customer_details.email, name: checkoutSession.customer_details.name || 'Customer' };
            }
            
            console.log('Checkout Session completed:', session.id);

            // First, save the order to the database
            const db = getDbPool();
            const result = await db.query(
                'INSERT INTO orders (order_id, amount_total, customer_email, line_items) VALUES ($1, $2, $3, $4) RETURNING *',
                [session.id, session.amount_total / 100, customer.email, JSON.stringify(session.line_items.data)]
            );
            console.log('Order saved to database:', result.rows[0].order_id);

            // Now, handle email sending with specific error logging
            const transporter = getTransporter();
            
            const formatCustomDetails = (metadata) => {
                if (!metadata || !metadata.custom_details) {
                    return '';
                }
                const customDetails = JSON.parse(metadata.custom_details);
                let detailsHtml = '<h4>Custom Details:</h4><ul>';
                for (const part in customDetails) {
                    const formattedPart = part.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                    if (part.includes('eye') || part.includes('mouth')) {
                         detailsHtml += `<li><b>${formattedPart}:</b> ${customDetails[part] === 'Static' ? 'Static' : 'Customized'}</li>`;
                    } else {
                        detailsHtml += `<li><b>${formattedPart}:</b> ${customDetails[part].split('/').pop().split('?')[0]}</li>`;
                    }
                }
                detailsHtml += '</ul>';
                return detailsHtml;
            };
            

            const lineItemsHtml = session.line_items.data.map(item => {
                const itemDetailsHtml = formatCustomDetails(item.price.product.metadata);
                return `
                    <li>
                        ${item.quantity} x ${item.description} - $${(item.amount_total / 100).toFixed(2)}
                        ${itemDetailsHtml}
                    </li>
                `;
            }).join('');
            
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
                subject: `NEW ORDER #${session.id.slice(-8)} from ${customer.name || 'Customer'}`,
                html: `
                    <h1>New Order Received!</h1>
                    <p><b>Order ID:</b> ${session.id}</p>
                    <p><b>Customer Name:</b> ${customer.name || 'N/A'}</p>
                    <p><b>Customer Email:</b> ${customer.email || 'N/A'}</p>
                    <hr>
                    <h3>Order Summary:</h3>
                    <ul>${lineItemsHtml}</ul>
                    <p><b>Total:</b> $${(session.amount_total / 100).toFixed(2)}</p>
                    <hr>
                    <h3>Shipping Address:</h3>
                    <p>
                        ${session.shipping_details ? session.shipping_details.name : 'N/A'}<br>
                        ${session.shipping_details ? (session.shipping_details.address.line1 || 'N/A') : ''}${session.shipping_details && session.shipping_details.address.line2 ? '<br>' + session.shipping_details.address.line2 : ''}<br>
                        ${session.shipping_details ? (session.shipping_details.address.city || 'N/A') : ''}, ${session.shipping_details ? (session.shipping_details.address.state || 'N/A') : ''} ${session.shipping_details ? (session.shipping_details.address.postal_code || 'N/A') : ''}<br>
                        ${session.shipping_details ? (session.shipping_details.address.country || 'N/A') : ''}
                    </p>
                `,
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
    
    // FIX: Ensure cart is an array and not empty before mapping
    if (!Array.isArray(cart) || cart.length === 0) {
        console.error("Error creating checkout session: Cart is empty or invalid.");
        return res.status(400).json({ error: 'Cart is empty or invalid.' });
    }
    
    const finalLineItems = cart.map(item => {
        // FIX: Add robust price parsing to handle different formats and prevent errors
        let priceValue;
        if (item.price && typeof item.price === 'string') {
            const sanitizedPrice = item.price.replace(/[$,]/g, '');
            priceValue = Math.round(parseFloat(sanitizedPrice) * 100);
        } else if (typeof item.price === 'number') {
            priceValue = Math.round(item.price * 100);
        } else {
            console.error(`Error: Invalid price for item "${item.name || 'Unknown Item'}". Price received:`, item.price);
            return null; // Return null for invalid items
        }

        if (isNaN(priceValue)) {
            console.error(`Error: Could not parse price for item "${item.name || 'Unknown Item'}". Price received:`, item.price);
            return null;
        }

        const metadata = item.images ? { custom_details: JSON.stringify(item.images) } : {};
        const image = item.images ? item.images.head : item.image;
        
        return {
            price_data: {
                currency: 'usd',
                product_data: {
                    name: item.name,
                    images: [image],
                    metadata: metadata
                },
                unit_amount: priceValue,
            },
            quantity: item.quantity,
        };
    }).filter(item => item !== null); // Filter out any items that failed validation

    if (finalLineItems.length === 0) {
        console.error("Error creating checkout session: All cart items failed validation.");
        return res.status(400).json({ error: 'All cart items failed validation.' });
    }

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: finalLineItems,
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

        const shippingDetails = session.shipping_details;
        const formattedLineItems = session.line_items.data.map(item => ({
            description: item.description,
            quantity: item.quantity,
            amount_total: item.amount_total / 100,
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
