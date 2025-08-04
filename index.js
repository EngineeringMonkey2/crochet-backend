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
                expand: ['line_items', 'line_items.data.price', 'line_items.data.price.product', 'customer'],
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

            // Generate line items HTML for customer email
            const lineItemsHtml = session.line_items.data.map(item => 
                `<li>${item.quantity} x ${item.description} - $${(item.amount_total / 100).toFixed(2)}</li>`
            ).join('');
            
            // Generate detailed line items HTML for owner email
            let ownerLineItemsHtml = '';
            for (const item of session.line_items.data) {
                let itemHtml = `<div style="border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px;">`;
                itemHtml += `<h4 style="margin-top: 0;">${item.quantity} x ${item.description} - ${(item.amount_total / 100).toFixed(2)}</h4>`;
                
                // Check if this is a custom monkey by checking the product name
                if (item.description === 'Custom Monkey') {
                    console.log('Processing Custom Monkey item...');
                    let metadata = {};
                    
                    // Try different ways to get the metadata
                    try {
                        // First check if metadata is already in the line item
                        if (item.price && item.price.metadata) {
                            metadata = item.price.metadata;
                            console.log('Found metadata in price:', metadata);
                        }
                        
                        // If not, check if it's in the product
                        if (Object.keys(metadata).length === 0 && item.price && item.price.product) {
                            // If product is just an ID string, fetch it
                            if (typeof item.price.product === 'string') {
                                console.log('Fetching product:', item.price.product);
                                const product = await stripe.products.retrieve(item.price.product);
                                metadata = product.metadata || {};
                                console.log('Retrieved product metadata:', metadata);
                            } else if (item.price.product.metadata) {
                                // If product is already expanded
                                metadata = item.price.product.metadata;
                                console.log('Found metadata in expanded product:', metadata);
                            }
                        }
                    } catch (error) {
                        console.error('Error retrieving metadata:', error);
                    }
                    
                    // Check if we have custom monkey metadata
                    const hasCustomParts = metadata.head || metadata.body || metadata.tail || 
                                         metadata.left_ear || metadata.right_ear || 
                                         metadata.left_arm || metadata.right_arm || metadata.legs;
                    
                    if (hasCustomParts) {
                        itemHtml += `<p><strong>Custom Details:</strong></p>`;
                        itemHtml += `<ul style="list-style-type: none; padding-left: 20px;">`;
                        
                        // List all custom parts in a specific order
                        const partMappings = {
                            'head': 'Head',
                            'left_ear': 'Left Ear',
                            'right_ear': 'Right Ear', 
                            'body': 'Body',
                            'left_arm': 'Left Arm',
                            'right_arm': 'Right Arm',
                            'legs': 'Legs',
                            'tail': 'Tail'
                        };
                        
                        for (const [key, label] of Object.entries(partMappings)) {
                            if (metadata[key]) {
                                itemHtml += `<li><strong>${label}:</strong> ${metadata[key]}</li>`;
                            }
                        }
                        
                        itemHtml += `</ul>`;
                    } else {
                        console.log('No custom parts found in metadata');
                        itemHtml += `<p><em>Custom details not available</em></p>`;
                    }
                }
                
                itemHtml += `</div>`;
                ownerLineItemsHtml += itemHtml;
            }
            
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

            // Updated email template for the store owner with custom details
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
                    <h3>Order Details:</h3>
                    ${ownerLineItemsHtml}
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

// This global middleware should come AFTER the webhook route
app.use(express.json());
app.use(cors({ origin: frontendUrl, credentials: true }));

// Session configuration
const sessionStore = new PgSession({ 
    pool: getDbPool(), 
    tableName: 'sessions',
    createTableIfMissing: true // Add this to auto-create the sessions table
});

app.use(session({
    store: sessionStore,
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
    
    console.log('Creating checkout session with cart:', JSON.stringify(cart, null, 2));
    
    // Convert cart items to Stripe line item format
    const lineItems = cart.map(item => {
        const lineItem = {
            price_data: {
                currency: 'usd',
                product_data: {
                    name: item.name,
                    images: item.image ? [item.image] : []
                },
                unit_amount: Math.round(parseFloat(item.price.replace('

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
//this one is the working one, '')) * 100), // Stripe expects cents
            },
            quantity: item.quantity,
        };
        
        // If this is a custom monkey (has images object), add the parts to metadata
        if (item.images && item.name === 'Custom Monkey') {
            console.log('Processing custom monkey with images:', item.images);
            
            // Initialize metadata object
            lineItem.price_data.product_data.metadata = {};
            
            // Add each custom part to the metadata
            const parts = ['head', 'left-ear', 'right-ear', 'body', 'left-arm', 'right-arm', 'legs', 'tail'];
            for (const part of parts) {
                if (item.images[part]) {
                    // Stripe metadata keys must use underscores instead of hyphens
                    const metadataKey = part.replace(/-/g, '_');
                    // Extract just the filename from the URL for brevity
                    const filename = item.images[part].split('/').pop();
                    lineItem.price_data.product_data.metadata[metadataKey] = filename;
                }
            }
            
            console.log('Custom monkey metadata:', lineItem.price_data.product_data.metadata);
        }
        
        return lineItem;
    });

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
//this one is the working one