const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
const serviceAccount = require('firebase-service-account-key.json'); 

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Signup Route
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 8);

        // Save user data to Firestore
        const userDocRef = db.collection('users').doc(email); // Use email as the document ID
        const userDoc = await userDocRef.get();

        if (userDoc.exists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        await userDocRef.set({
            name,
            email,
            password: hashedPassword
        });

        res.json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error signing up:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Fetch user data from Firestore
        const userDocRef = db.collection('users').doc(email);
        const userDoc = await userDocRef.get();

        if (!userDoc.exists) {
            return res.status(400).json({ message: 'User not found' });
        }

        const user = userDoc.data();

        // Check if password is correct
        const isValidPassword = bcrypt.compareSync(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ email: user.email }, 'secretkey', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
