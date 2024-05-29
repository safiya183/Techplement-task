

const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt'); // Add bcrypt for password hashing

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root123',
    database: 'signlog'
});

const app = express();

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if user is logged in
const requireLogin = (req, res, next) => {
    if (req.session.loggedin) {
        // User is logged in, proceed to the next middleware
        next();
    } else {
        // User is not logged in, redirect to login page
        res.redirect('/login');
    }
};

// Route handler for serving SignUp.html when accessing root URL
app.get('/', function (req, res) {
    // Check if user is logged in before serving main.html
    if (req.session.loggedin) {
        res.sendFile(path.join(__dirname, 'public', 'main.html'));
    } else {
        res.redirect('/login');
    }
});

// Route handler for serving login.html
app.get('/login', function (req, res) {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle sign-up
app.post('/signup', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO logup (uname, email, pass) VALUES (?, ?, ?)";
    connection.query(sql, [username, email, hashedPassword], function (err, result) {
        if (err) {
            console.error(err);
            res.status(500).send('Server error');
        } else {
            res.redirect('/login');
        }
    });
});

// Handle login
app.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const sql = 'SELECT * FROM logup WHERE uname = ?';
    connection.query(sql, [username], async function (err, results) {
        if (err) throw err;

        if (results.length > 0) {
            const comparison = await bcrypt.compare(password, results[0].pass);
            if (comparison) {
                req.session.loggedin = true;
                req.session.username = username;
                res.redirect('/main.html');
            } else {
                res.status(401).send('Invalid Username or Password');
            }
        } else {
            res.status(401).send('Invalid Username or Password');
        }
    });
});

// Start the server
const PORT = process.env.PORT || 8989;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
