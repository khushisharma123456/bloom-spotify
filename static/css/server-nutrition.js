require('dotenv').config(); // Load .env variables

const express = require('express');
const path = require('path');
const app = express();

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

// Serve static files (CSS, JS, images) - RESTRICTED to only asset folders, NOT HTML at root
app.use('/css', express.static(path.join(__dirname))); // Serve CSS files
app.use('/Images', express.static(path.join(__dirname, '..', 'Images'))); // Serve images
app.use('/images', express.static(path.join(__dirname, '..', 'Images'))); // Alternative path for images
app.use('/js', express.static(path.join(__dirname, '..', 'js'))); // Serve JS files
app.use('/fonts', express.static(path.join(__dirname, '..', 'fonts'))); // Serve font files

// Import routes
const remedyRoutes = require('./routes/remedy');

// Debug middleware to log all requests
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// Remedy routes - must be before home route
app.use('/remedy', remedyRoutes);

// Home route - serve Nutrition.html or Nutrition.ejs
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'Nutrition.html'));
    // OR if using EJS:
    // res.render('Nutrition', { recipes: recipesData.recipes });
});

// Block yoga routes
app.get('/yoga*', (req, res) => {
    res.redirect('/');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err.stack);
    res.status(500).send(`
        <h1>Error</h1>
        <p>Something went wrong. Please try again.</p>
        <p>Error: ${err.message}</p>
        <button onclick="window.history.back()">Go Back</button>
    `);
});

// 404 handler - must be last
app.use((req, res) => {
    console.log('404 Not Found:', req.url);
    res.status(404).send(`
        <h1>Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <button onclick="window.history.back()">Go Back</button>
    `);
});

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Views directory:', path.join(__dirname, '..', 'views'));
});