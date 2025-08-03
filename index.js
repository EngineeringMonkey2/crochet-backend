// server.js (Rewritten for a standard Node.js hosting platform like Render)

// --- DEPENDENCIES ---
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const stripe = require('stripe');
const { Pool } = require('pg'); // PostgreSQL client

// --- INITIALIZATION ---
const app = express();

// IMPORTANT: On Render, you will set these as environment variables in the dashboard.
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;
const emailRecipient = process.env.EMAIL_RECIPIENT;
const databaseUrl = process.env.DATABASE_URL; // This is provided by Render for your database

// --- LAZY INITIALIZATION OF SERVICES ---
// This pattern ensures services are only created once, when first needed.
let stripeInstance;
let transporter;
let dbPool;

function getStripe() {
    if (!stripeInstance) {
        if (!stripeSecretKey) throw new Error("Stripe secret key is not configured in environment variables.");
        stripeInstance = stripe(stripeSecretKey);
    }
    return stripeInstance;
}

function getTransporter() {
    if (!transporter) {
        if (!emailUser || !emailPass) throw new Error("Email credentials are not configured in environment variables.");
        transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: emailUser, pass: emailPass },
        });
    }
    return transporter;
}

function getDbPool() {
    if (!dbPool) {
        if (!databaseUrl) throw new Error("Database URL is not configured in environment variables.");
        // This configuration is standard for connecting to hosted databases like on Render
        dbPool = new Pool({
            connectionString: databaseUrl,
            ssl: { rejectUnauthorized: false }
        });
    }
    return dbPool;
}

// --- MIDDLEWARE ---
// Define the websites that are allowed to connect to this backend
const allowedOrigins = [
  'https://nobiliscrochet.com',
  'https://www.nobiliscrochet.com',
  // You might want to add your Cloudflare Pages preview URL here for testing
];
app.use(cors({ origin: allowedOrigins }));

// This special middleware is for the Stripe webhook, which needs the raw request body.
// For all other routes, we parse the body as JSON.
app.use((req, res, next) => {
    if (req.originalUrl.includes('/stripe-webhook')) {
        next();
    } else {
        express.json()(req, res, next);
    }
});

// --- HELPER FUNCTIONS ---
async function sendOrderNotificationEmail(session) {
    const stripeClient = getStripe();
    const mailTransporter = getTransporter();
    try {
        const sessionWithLineItems = await stripeClient.checkout.sessions.retrieve(
            session.id,
            { expand: ['line_items', 'line_items.data.price.product', 'shipping_cost.shipping_rate'] }
        );
        const customerEmail = sessionWithLineItems.customer_details.email;
        const lineItems = sessionWithLineItems.line_items.data;
        const total = (sessionWithLineItems.amount_total / 100).toFixed(2);
        const address = sessionWithLineItems.shipping_details.address;
        const shippingHtml = `<p><b>${sessionWithLineItems.shipping_details.name}</b><br>${address.line1}${address.line2 ? '<br>' + address.line2 : ''}<br>${address.city}, ${address.state} ${address.postal_code}<br>${address.country}</p>`;
        let itemsHtml = lineItems.map(item => `<div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #eee;"><p><b>Item:</b> ${item.description}</p><p><b>Quantity:</b> ${item.quantity}</p><p><b>Price:</b> $${(item.price.unit_amount / 100).toFixed(2)}</p></div>`).join('');
        const mailOptions = {
            from: emailUser,
            to: emailRecipient,
            subject: `New Order Received! - #${session.id.slice(-8)}`,
            html: `<div style="font-family: Arial, sans-serif; line-height: 1.6;"><h2>You've received a new order!</h2><p><b>Order ID:</b> ${session.id}</p><p><b>Customer Email:</b> <a href="mailto:${customerEmail}">${customerEmail}</a></p><hr><h3>Shipping Address:</h3>${shippingHtml}<hr><h3>Order Details:</h3>${itemsHtml}<hr><h3 style="text-align: right;">Total: $${total}</h3></div>`,
        };
        await mailTransporter.sendMail(mailOptions);
        console.log('✅ Order notification email sent successfully.');
    } catch (error) {
        console.error('❌ Error sending order notification email:', error);
    }
}

// --- API ROUTES ---

app.post('/create-checkout-session', async (req, res) => {
    const { cart } = req.body;
    const stripeClient = getStripe();
    if (!cart || cart.length === 0) {
        return res.status(400).send({ error: 'Cart is empty.' });
    }
    try {
        const line_items = cart.map(item => {
            const priceInCents = Math.round(parseFloat(item.price.replace('$', '')) * 100);
            const metadata = { productId: item.id };
            if (String(item.id).startsWith('custom-')) {
                const shortCustomDetails = {};
                for (const part in item.images) {
                    shortCustomDetails[part] = item.images[part].split('/').pop();
                }
                metadata.custom_details = JSON.stringify(shortCustomDetails);
            }
            return {
                price_data: {
                    currency: 'usd',
                    product_data: { name: item.name, images: [item.image || (item.images ? item.images.head : null)].filter(Boolean), metadata: metadata },
                    unit_amount: priceInCents,
                },
                quantity: item.quantity,
            };
        });
        const session = await stripeClient.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: line_items,
            mode: 'payment',
            shipping_address_collection: { allowed_countries: ['US', 'CA'] },
            success_url: `${req.headers.origin}/receipt.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.headers.origin}/cart.html`,
        });
        res.json({ url: session.url });
    } catch (error) {
        console.error('Error creating Stripe session:', error);
        res.status(500).send({ error: error.message });
    }
});

app.get('/order-details', async (req, res) => {
    const { session_id } = req.query;
    const stripeClient = getStripe();
    try {
        const session = await stripeClient.checkout.sessions.retrieve(session_id, {
            expand: ['line_items', 'line_items.data.price.product', 'shipping_cost.shipping_rate'],
        });
        res.json(session);
    } catch (error) {
        console.error('Error retrieving session details:', error);
        res.status(500).json({ error: 'Could not retrieve session details.' });
    }
});

app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const stripeClient = getStripe();
    let event;
    try {
        event = stripeClient.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.log(`❌ Webhook signature verification failed: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('✅ Checkout session was successful! Fulfilling order...');
        await sendOrderNotificationEmail(session);

        // ** This is the new code to save the order to your PostgreSQL database **
        try {
            const sessionWithLineItems = await stripeClient.checkout.sessions.retrieve(session.id, { expand: ['line_items'] });
            const lineItemsWithProducts = await Promise.all(
                sessionWithLineItems.line_items.data.map(async (item) => {
                    const product = await stripeClient.products.retrieve(item.price.product);
                    return { description: item.description, quantity: item.quantity, amount_total: item.amount_total / 100, price: item.price.unit_amount / 100, productId: product.metadata.productId || null };
                })
            );

            // This is the SQL query to insert the new order into the 'orders' table
            const insertQuery = `
                INSERT INTO orders(order_id, customer_email, amount_total, shipping_details, line_items, status)
                VALUES($1, $2, $3, $4, $5, $6)
            `;
            const values = [
                session.id,
                session.customer_details.email,
                session.amount_total / 100,
                session.shipping_details || null,
                JSON.stringify(lineItemsWithProducts), // Convert the array of items to a string to store in the JSONB column
                'completed'
            ];

            const db = getDbPool();
            await db.query(insertQuery, values);
            console.log(`✅ Order ${session.id} saved to PostgreSQL.`);

        } catch (error) {
            console.error('❌ Error saving order to PostgreSQL:', error);
        }
    }
    res.json({ received: true });
});


// --- START THE SERVER ---
// This is the standard way to start a Node.js server.
// Render will use the PORT environment variable it provides.
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
