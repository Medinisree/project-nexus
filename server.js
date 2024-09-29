const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const users = []; // Temporary in-memory user storage

// Signup Route
app.post('/signup', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = { name, email, password: hashedPassword };
    users.push(user);
    res.json({ message: 'User registered successfully' });
});

// Login Route
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isValidPassword = bcrypt.compareSync(password, user.password);
    if (!isValidPassword) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ email: user.email }, 'secretkey', { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
