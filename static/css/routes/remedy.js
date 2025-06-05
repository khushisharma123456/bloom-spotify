const express = require('express');
const router = express.Router();
const { getGeminiRemedy } = require('../utility/gemini');

// Route: /:name (since we're already mounted at /remedy)
router.get('/:name', async (req, res) => {
    try {
        const remedyName = req.params.name;
        console.log('Fetching remedy:', remedyName);

        if (!remedyName) {
            throw new Error('Remedy name is required');
        }

        const prompt = `
            You are an expert in women's wellness and Ayurvedic remedies.
            Provide a detailed recipe for "${remedyName}" in JSON format with these fields:
            {
                "name": "Exact name of the remedy",
                "image": "A descriptive image URL that represents this remedy (e.g., 'https://example.com/ginger-tea.jpg' or leave blank)",
                "badge": "Main health benefit category (e.g., 'Hormone Balance', 'Pain Relief', 'Bloating')",
                "time": "Total preparation time (e.g., '15 min', 'Overnight')",
                "calories": "Approximate calories per serving (e.g., '120 cal')",
                "description": "A 2-3 sentence summary explaining what this remedy is and its primary benefits for women's health",
                "ingredients": [
                    "List each ingredient with exact quantities and units",
                    "Include any special notes about ingredient quality or preparation"
                ],
                "steps": [
                    "List detailed preparation steps in order",
                    "Include timing, temperature, and any special techniques",
                    "Add any important notes about preparation"
                ],
                "benefits": "A comprehensive paragraph explaining the health benefits, focusing on:
                    - How it helps with women's health issues
                    - Specific benefits for menstrual health
                    - Any scientific or traditional evidence
                    - Best time to consume
                    - Any precautions or contraindications"
            }
            Make the response detailed and practical, focusing on women's wellness.
            Respond ONLY with valid JSON, no extra text.
        `;

        console.log('Sending prompt to Gemini API...');
        let geminiResponse = await getGeminiRemedy(prompt);
        // Remove markdown code block markers if present
        geminiResponse = geminiResponse.replace(/```(json)?/g, '').trim();
        console.log('Raw Gemini output:', geminiResponse);
        let remedy;
        try {
            remedy = JSON.parse(geminiResponse);
        } catch (e) {
            // Fallback remedy object if parsing fails
            remedy = {
                name: "Remedy Not Found",
                image: "",
                badge: "",
                time: "",
                calories: "",
                description: "Sorry, we couldn't fetch this remedy.",
                ingredients: [],
                steps: [],
                benefits: ""
            };
        }
        res.render('remedy', { remedy });
    } catch (err) {
        console.error('Error in remedy route:', err);
        res.status(500).send(`
            <h1>Error Loading Remedy</h1>
            <p>Sorry, we couldn't load the remedy details. Please try again later.</p>
            <p>Error: ${err.message}</p>
            <button onclick="window.history.back()">Go Back</button>
        `);
    }
});

// Add a catch-all route to prevent other routes from interfering
router.get('/*', (req, res, next) => {
    next();
});

module.exports = router;