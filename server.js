const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/webtoonDB')
    .then(() => {
        console.log('MongoDB connected successfully');
    }).catch(err => {
        console.error('MongoDB connection error:', err);
    });

// User schema
const userSchema = new mongoose.Schema({
    username: String,
    email: { type: String, required: true, unique: true }, // Ensuring email is unique
    password: { type: String, required: true } // Making password required
});

// Webtoon schema
const webtoonSchema = new mongoose.Schema({
    id: String,
    title: String,
    description: String,
    characters: String,
});

const User = mongoose.model('User', userSchema);
const Webtoon = mongoose.model('Webtoon', webtoonSchema);

// Middleware to serve static files and parse request bodies
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Secret key for JWT from environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware to verify JWT
function authenticateJWT(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Forbidden: Token is invalid or expired' });
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({ message: 'Unauthorized: Token is required' });
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index1.html'));
});

app.get('/search-webtoons', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'search-webtoons.html'));
});

app.get('/get-webtoons', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'get-webtoons.html'));
});

app.get('/post-webtoon', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'post-webtoons.html'));
});

app.get('/delete-webtoon', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'delete-webtoons.html'));
});

// User login
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = { username, email, password: hashedPassword };
    users.push(newUser);

    res.status(201).json({ message: 'User created successfully' });
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find user by email
    const user = users.find(user => user.email === email);
    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    // Store token in local storage or send it to the client
    res.json({ token, message: 'Login successful!', redirect: '/index' }); // Updated to '/index'
});

// Endpoint to serve another HTML page
app.get('/index2', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index2.html'));
});

// Logout - client should remove token
app.get('/logout', (req, res) => {
    // In JWT, simply remove the token on the client-side to log out
    res.send('Logged out successfully');
});

// Fetch all webtoons or search by title
app.get('/api/webtoons', authenticateJWT, async (req, res) => {
    const { title } = req.query;
    try {
        const webtoons = title
            ? await Webtoon.find({ title: { $regex: title, $options: 'i' } }) // Case-insensitive search
            : await Webtoon.find();
        res.json(webtoons);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching webtoons' });
    }
});

// Post a new webtoon
app.post('/api/webtoons', authenticateJWT, async (req, res) => {
    const { id, title, description, characters } = req.body;
    const newWebtoon = new Webtoon({ id, title, description, characters });
    
    try {
        await newWebtoon.save();
        res.json({ message: 'Webtoon added successfully!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error adding webtoon' });
    }
});

// Delete a webtoon by ID
app.delete('/api/webtoons/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await Webtoon.deleteOne({ id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: `Webtoon with ID ${id} not found.` });
        }
        res.json({ message: `Webtoon with ID ${id} deleted successfully!` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error deleting webtoon' });
    }
});

// Starting the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
