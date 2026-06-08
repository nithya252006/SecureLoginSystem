require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');

const app = express();

// --- Middleware ---
app.use(helmet()); // Protects headers from common vulnerabilities
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Secure Session Management
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Prevents XSS attacks from reading the session cookie
        secure: false,  // Set to true if running on HTTPS
        maxAge: 1000 * 60 * 30 // Session expires in 30 minutes
    }
}));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Database connected securely.'))
    .catch(err => console.error('Database connection error:', err));

// Auth Middleware to protect routes
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        return next();
    }
    res.status(401).json({ message: "Unauthorized access. Please log in." });
};

// --- Routes ---

// 1. User Registration Route (With Input Validation & Hashing)
app.post('/api/register', [
    body('username').trim().isAlphanumeric().withMessage('Username must be alphanumeric').isLength({ min: 3 }),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { username, password } = req.body;

        // Prevent duplicate user registration
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username is already taken' });
        }

        // Feature 1: Password Hashing using bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 2. User Login Route
app.post('/api/login', [
    body('username').trim().escape(),
    body('password').exists()
], async (req, res) => {
    try {
        const { username, password } = req.body;

        // Querying with Object-Document Mapping protects against parameter injection
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Feature 1: Verify hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Feature 3: Establish Session
        req.session.userId = user._id;
        res.status(200).json({ message: 'Login successful!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 3. Protected Dashboard Route
app.get('/api/dashboard', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        res.status(200).json({ message: `Welcome to your secure portal, ${user.username}!` });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 4. Session Logout Route
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out. Try again.' });
        }
        res.clearCookie('connect.sid'); // Clear session cookie from client browser
        res.status(200).json({ message: 'Logout successful!' });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));
