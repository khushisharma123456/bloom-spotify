const axios = require('axios');

async function getGeminiRemedy(prompt) {
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
        console.error('GEMINI_API_KEY is not set in .env file');
        throw new Error('API key not configured');
    }

    const url = `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent?key=${apiKey}`;

    
    console.log('Sending request to Gemini API...');
    console.log('Prompt:', prompt);
    
    try {
        const response = await axios.post(url, {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                temperature: 0.7,
                topK: 40,
                topP: 0.95,
                maxOutputTokens: 2048,
            }
        });

        if (!response.data || !response.data.candidates || !response.data.candidates[0]) {
            console.error('Unexpected response structure:', JSON.stringify(response.data, null, 2));
            throw new Error('Invalid response from Gemini API');
        }

        const result = response.data.candidates[0].content.parts[0].text;
        console.log('Successfully received response from Gemini API');
        
        // Try to parse the response as JSON to validate it
        try {
            const jsonResult = JSON.parse(result);
            console.log('Successfully parsed JSON response');
            return result; // Return the original string to maintain formatting
        } catch (parseError) {
            console.error('Error parsing Gemini response as JSON:', parseError);
            console.error('Raw response:', result);
            throw new Error('Invalid JSON response from Gemini API');
        }
    } catch (error) {
        if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            console.error('Gemini API error response:', {
                status: error.response.status,
                data: error.response.data,
                headers: error.response.headers
            });
            throw new Error(`Gemini API error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
        } else if (error.request) {
            // The request was made but no response was received
            console.error('No response received from Gemini API:', error.request);
            throw new Error('No response received from Gemini API');
        } else {
            // Something happened in setting up the request that triggered an Error
            console.error('Error setting up Gemini API request:', error.message);
            throw new Error(`Error setting up Gemini API request: ${error.message}`);
        }
    }
}

module.exports = { getGeminiRemedy };