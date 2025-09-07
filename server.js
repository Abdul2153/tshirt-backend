// server.js
const express = require('express');
const Razorpay = require('razorpay');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET; // Replace with a long, random string

const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');


// --- Middleware ---
const corsOptions = { origin: 'https://printastic-tshirt.netlify.app', optionsSuccessStatus: 200 };
app.use(cors(corsOptions));
app.use(express.json());

// --- 1. CONNECT TO MONGODB ATLAS ---
const mongoURI = process.env.MONGO_URI; // <-- PASTE YOUR CONNECTION STRING HERE
mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB connected successfully.'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- 2. DEFINE THE USER SCHEMA (The blueprint for user data) ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    address: { type: String }
});
const User = mongoose.model('User', UserSchema);

// NEW: Order Schema to store purchase details
const OrderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    customerName: { type: String, required: true },
    products: { type: Array, required: true },
    totalAmount: { type: Number, required: true },
    shippingAddress: { type: String, required: true },
    razorpayOrderId: { type: String, required: true },
    razorpayPaymentId: { type: String },
    paymentStatus: { type: String, default: 'Pending' },
    orderStatus: { type: String, default: 'Ongoing' },
    orderDate: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

// --- Razorpay Instance (keep your keys here) ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// --- MIDDLEWARE TO VERIFY LOGIN TOKEN ---
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid.' });
    }
};

// NEW: Configure Cloudinary using Environment Variables
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// NEW: Configure Multer to use Cloudinary for storage
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'tshirt-designs', // A folder name in your Cloudinary account
        format: async (req, file) => 'png', // supports promises as well
        public_id: (req, file) => `design-${Date.now()}`,
    },
});
const upload = multer({ storage: storage });

// --- API ROUTES ---

// 3. SIGNUP ROUTE
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password, address } = req.body;
        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        // Hash the password for security
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // Create a new user instance
        user = new User({
            name,
            email,
            password: hashedPassword,
            address
        });
        // Save the user to the database
        await user.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).send('Server error during signup.');
    }
});

// 4. LOGIN ROUTE
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        // If credentials are correct, create a login token (optional but good practice)
        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }); // Replace 'yourSecretKey'
        res.json({ message: 'Login successful!', token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Server error during login.');
    }
});

// Route to get a single user's details by their ID
app.get('/user/:id', authMiddleware, async (req, res) => {
    try {
        // Check if the requested ID matches the ID from the user's token
        if (req.params.id !== req.user.id) {
            return res.status(403).json({ message: 'User not authorized.' });
        }

        const user = await User.findById(req.params.id).select('-password'); 
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).send('Server error');
    }
});

// CORRECTED /create-order route
// In server.js
app.post('/create-order', authMiddleware, async (req, res) => {
    try {
        const { cart, address, userName } = req.body;
        if (!cart || cart.length === 0) return res.status(400).send('Cart is empty');

        let totalAmount = 0;
        cart.forEach(item => { totalAmount += parseFloat(item.price); });

        // CORRECTED: This now saves all product details, including the custom URL for each item
        const formattedProducts = cart.map(item => ({
            name: item.name,
            price: item.price,
            image: item.image,
            customDesignUrl: item.customDesignUrl || null
        }));

        const razorpayOrder = await razorpay.orders.create({
            amount: totalAmount * 100,
            currency: 'INR',
            receipt: `receipt_order_${new Date().getTime()}`,
            notes: { items: cart.map(item => item.name).join(', ') }
        });
        if (!razorpayOrder) return res.status(500).send('Error creating Razorpay order');

        const newOrder = new Order({
            userId: req.user.id,
            customerName: userName,
            products: formattedProducts, // Use the new, complete product list
            totalAmount: totalAmount,
            shippingAddress: address,
            razorpayOrderId: razorpayOrder.id,
            paymentStatus: 'Pending'
        });
        await newOrder.save();
        res.json(razorpayOrder);
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// NEW: /verify-payment route
app.post('/verify-payment', async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        
        // This is a security step from Razorpay's docs
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET) // Use your Key Secret
            .update(body.toString())
            .digest('hex');

        if (expectedSignature === razorpay_signature) {
            // Payment is legitimate, now update our database
            const updatedOrder = await Order.findOneAndUpdate(
                { razorpayOrderId: razorpay_order_id },
                {
                    paymentStatus: 'Paid',
                    razorpayPaymentId: razorpay_payment_id
                },
                { new: true } // Return the updated document
            );
            res.status(200).json({ status: 'success', order: updatedOrder });
        } else {
            res.status(400).json({ status: 'failure', message: 'Payment verification failed.' });
        }
    } catch (error) {
        console.error('Verify payment error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// NEW: Route to get all orders for the currently logged-in user
app.get('/my-orders', authMiddleware, async (req, res) => {
    try {
        // Find orders where the 'userId' matches the ID from the authenticated user's token
        const orders = await Order.find({ userId: req.user.id }).sort({ orderDate: -1 }); // Sort by newest first
        res.json(orders);
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).send('Server Error');
    }
});

// NEW: Route to handle image uploads
app.post('/upload-design', upload.single('design'), (req, res) => {
    // 'design' is the name of the input field in the HTML form
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }
    // Multer and Cloudinary have handled the upload.
    // req.file.path contains the secure URL of the uploaded image.
    res.json({ imageUrl: req.file.path });
});

// --- ADMIN ROUTES ---

// 1. A route to get all orders
app.get('/admin/orders', async (req, res) => {
    try {
        // UPDATED: .populate() will now automatically include the name and email
        // of the user associated with each order.
        const orders = await Order.find({ paymentStatus: 'Paid' })
            .populate('userId', 'name email') // This "joins" the user data
            .sort({ orderDate: -1 });
        res.json(orders);
    } catch (error) {
        console.error('Admin get orders error:', error);
        res.status(500).send('Server Error');
    }
});

// 2. A route to mark an order as "Completed"
app.post('/admin/orders/:id/complete', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { orderStatus: 'Completed' },
            { new: true }
        );
        res.json(order);
    } catch (error) {
        console.error('Admin update order error:', error);
        res.status(500).send('Server Error');
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running beautifully on http://localhost:${PORT}`);
});
