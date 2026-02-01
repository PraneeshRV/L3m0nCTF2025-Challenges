const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = 5001;

// --- SETUP: AUTO-GENERATE FILES ---
const BASE_DIR = __dirname;
const DOCS_DIR = path.join(BASE_DIR, 'documents');
const PUBLIC_DIR = path.join(DOCS_DIR, 'public');

if (fs.existsSync(DOCS_DIR)) {
    fs.rmSync(DOCS_DIR, { recursive: true, force: true });
}
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

fs.writeFileSync(path.join(PUBLIC_DIR, 'corporate_policy.txt'),
    "SHADOWCORP EMPLOYEE HANDBOOK v4.2\n" +
    "===================================\n" +
    "- All requisition orders are final.\n" +
    "- Standard employees are capped at Level 1 Clearance.\n"
);

fs.writeFileSync(path.join(DOCS_DIR, 'coupon'),
    "LEGACY PROMO CODE DETECTED\n" +
    "------------------------\n" +
    "Use this code at checkout for a discount:\n" +
    "Code: SHADOW_DISCOUNT\n" +
    "Value: $100.00 OFF\n"
);

// --- GAME CONFIGURATION ---
const ITEMS = {
    'flag': { name: 'The Shadow Flag', price: 1000, icon: '🚩', desc: 'Classified Material. Level 10 Clearance Required.' },
    'watch': { name: 'Tactical Watch', price: 150, icon: '⌚', desc: 'Standard issue timing device. Water resistant.' },
    'usb': { name: 'Encrypted USB', price: 50, icon: '💾', desc: '256-bit AES hardware encryption.' }
};

const users = {};
const carts = {};

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true
}));

app.locals.currency = (value) => {
    return "$" + value.toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// --- ROUTES ---

// 1. HOME PAGE
app.get('/', (req, res) => {
    const user = req.session.user ? users[req.session.user] : null;
    res.render('index', { user: req.session.user, balance: user ? user.balance : 0 });
});

// 2. SHOP PAGE
app.get('/shop', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const user = users[req.session.user];
    res.render('shop', {
        user: req.session.user,
        balance: user.balance,
        items: ITEMS
    });
});

// 3. CHECKOUT PAGE
app.get('/checkout', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const user = users[req.session.user];

    if (!carts[req.session.id]) {
        carts[req.session.id] = { item: null, discount: 0, coupons_applied: 0, locked: false };
    }
    const cart = carts[req.session.id];

    res.render('checkout', {
        user: req.session.user,
        balance: user.balance,
        cart: cart,
        items: ITEMS,
        msg: req.query.msg
    });
});

app.get('/doc_viewer', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    let filename = req.query.doc || 'corporate_policy.txt';
    let cleanName = filename.replace("../", "");
    const filePath = path.join(PUBLIC_DIR, cleanName);

    try {
        if (fs.existsSync(filePath)) {
            res.sendFile(filePath);
        } else {
            res.send(`ERROR: File '${cleanName}' not found.`);
        }
    } catch (e) {
        res.send(`ERROR: File '${cleanName}' not found.`);
    }
});

// --- CART LOGIC ---
app.post('/cart/add', (req, res) => {
    if (!req.session.user) return res.json({ status: 'error' });
    const itemKey = req.body.item;
    if (!ITEMS[itemKey]) return res.json({ status: 'error', msg: 'Invalid Item' });

    carts[req.session.id] = { item: itemKey, discount: 0, coupons_applied: 0, locked: false };
    return res.json({ status: 'success', msg: 'Added to Cart' });
});

app.post('/cart/clear', (req, res) => {
    if (req.session.id) {
        carts[req.session.id] = { item: null, discount: 0, coupons_applied: 0, locked: false };
    }
    return res.redirect('/checkout');
});

const COUPON_CODE = "SHADOW_DISCOUNT";
const COUPON_VALUE = 100;

app.post('/api/support/unlock_cart', (req, res) => {
    if (!req.session.user) return res.json({ status: 'error', msg: 'Login required' });
    const cart = carts[req.session.id];
    if (cart) {
        cart.locked = false;
        return res.json({ status: 'success', msg: 'Cart unlocked. Please try again.' });
    }
    return res.json({ status: 'error', msg: 'No cart found' });
});

app.post('/cart/apply_coupon', async (req, res) => {
    if (!req.session.user) return res.json({ status: 'error', msg: 'Login required' });

    const cart = carts[req.session.id];
    if (!cart || !cart.item) {
        return res.json({ status: 'error', msg: 'No item in cart' });
    }

    const code = req.body.code;
    if (code !== COUPON_CODE) {
        return res.json({ status: 'error', msg: 'Invalid Coupon' });
    }

    if (cart.coupons_applied > 0) {
        return res.json({ status: 'error', msg: 'Coupon already applied!' });
    }

    if (cart.locked) {
        return res.json({ status: 'error', msg: 'Transaction in progress. Please wait.' });
    }
    cart.locked = true;

    try {
        await sleep(500);

        cart.coupons_applied += 1;
        cart.discount += COUPON_VALUE;
    } catch (e) {
        console.error(e);
    } finally {
        cart.locked = false;
    }

    return res.json({ status: 'success', msg: `Coupon Applied! -$${COUPON_VALUE}` });
});

app.post('/checkout/pay', (req, res) => {
    if (!req.session.user) return res.json({ status: 'error' });
    const user = users[req.session.user];
    const cart = carts[req.session.id];

    if (!cart || !cart.item) return res.json({ status: 'error', msg: 'Cart is empty' });

    const basePrice = ITEMS[cart.item].price;
    const finalPrice = Math.max(0, basePrice - cart.discount);

    if (user.balance >= finalPrice) {
        user.balance -= finalPrice;

        const boughtItem = cart.item;
        carts[req.session.id] = { item: null, discount: 0, coupons_applied: 0, locked: false };

        if (boughtItem === 'flag') {
            const flagValue = process.env.FLAG || 'l3mon{l0cks_ar3_0nly_as_str0ng_as_th3_k3y_h0ld3r}';
            return res.json({ status: 'win', flag: flagValue });
        }
        return res.json({ status: 'success', msg: 'Purchase Successful!' });
    }
    return res.json({ status: 'error', msg: `Insufficient Funds. Need $${finalPrice}` });
});

app.post('/register', (req, res) => {
    const username = req.body.username;
    if (username) {
        users[username] = { balance: 100.00 };
        req.session.user = username;
        carts[req.session.id] = { item: null, discount: 0, coupons_applied: 0, locked: false };
    }
    res.redirect('/shop');
});

app.get('/logout', (req, res) => {
    if (req.session.id) delete carts[req.session.id];
    req.session.destroy();
    res.redirect('/');
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});
