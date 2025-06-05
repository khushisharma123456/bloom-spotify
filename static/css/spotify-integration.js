// Spotify Configuration
const SPOTIFY_CLIENT_ID = '6b770d2f043948dc9515d3a5f65a5113';
const REDIRECT_URI = 'http://localhost:5000/callback';
const SCOPES = [
    'playlist-modify-public',
    'playlist-modify-private',
    'user-top-read',
    'user-read-email',
    'user-read-private'
];

// Mood to Spotify parameters mapping
const MOOD_MAPPING = {
    happy: {
        seed_genres: 'pop',
        min_energy: 0.7,
        min_valence: 0.7,
        target_tempo: 120
    },
    sad: {
        seed_genres: 'acoustic',
        max_energy: 0.4,
        max_valence: 0.4,
        target_tempo: 80
    },
    angry: {
        seed_genres: 'rock,metal,rap',
        min_energy: 0.8,
        min_valence: 0.3,
        target_tempo: 140
    },
    energetic: {
        seed_genres: 'dance,edm,work-out',
        min_energy: 0.8,
        min_valence: 0.6,
        target_tempo: 130
    }
};

// Initialize Spotify integration
function initSpotify() {
    const loginButton = document.createElement('button');
    loginButton.id = 'spotify-login';
    loginButton.className = 'spotify-login-btn glass-card';
    loginButton.textContent = 'Connect with Spotify';
    loginButton.onclick = handleSpotifyLogin;
    
    const playlistDisplay = document.createElement('div');
    playlistDisplay.id = 'playlistDisplay';
    playlistDisplay.className = 'playlist-display glass-card';
    
    document.querySelector('.mood-selector').appendChild(loginButton);
    document.querySelector('.mood-selector').appendChild(playlistDisplay);
}

// Handle Spotify login
function handleSpotifyLogin() {
    const authUrl = new URL('https://accounts.spotify.com/authorize');
    const params = {
        client_id: SPOTIFY_CLIENT_ID,
        response_type: 'code',
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        show_dialog: true
    };
    
    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();
}

// Generate playlist based on mood
async function generatePlaylist(mood, rating) {
    const accessToken = sessionStorage.getItem('spotify_access_token');
    if (!accessToken) {
        showSpotifyLoginPrompt();
        return;
    }

    try {
        // Get user profile
        const userResponse = await fetch('https://api.spotify.com/v1/me', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        const userData = await userResponse.json();

        // Create playlist
        const playlistResponse = await fetch(`https://api.spotify.com/v1/users/${userData.id}/playlists`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: `${mood.charAt(0).toUpperCase() + mood.slice(1)} Mood Playlist`,
                description: `Generated based on your ${mood} mood (Rating: ${rating}/5)`
            })
        });
        const playlist = await playlistResponse.json();

        // Get recommendations based on mood
        const moodParams = MOOD_MAPPING[mood];
        const recommendationsResponse = await fetch(
            `https://api.spotify.com/v1/recommendations?` +
            new URLSearchParams({
                ...moodParams,
                limit: 20
            }), {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            }
        );
        const recommendations = await recommendationsResponse.json();

        // Add tracks to playlist
        const trackUris = recommendations.tracks.map(track => track.uri);
        await fetch(`https://api.spotify.com/v1/playlists/${playlist.id}/tracks`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ uris: trackUris })
        });

        // Display playlist
        displayPlaylist(playlist);
    } catch (error) {
        console.error('Error generating playlist:', error);
        showError('Failed to generate playlist. Please try again.');
    }
}

// Display playlist in the UI
function displayPlaylist(playlist) {
    const playlistDisplay = document.getElementById('playlistDisplay');
    playlistDisplay.innerHTML = `
        <h3>Your Mood Playlist</h3>
        <iframe src="https://open.spotify.com/embed/playlist/${playlist.id}"
                width="100%"
                height="380"
                frameborder="0"
                allowtransparency="true"
                allow="encrypted-media">
        </iframe>
        <a href="https://open.spotify.com/playlist/${playlist.id}" 
           target="_blank" 
           class="open-spotify-btn glass-card">
            Open in Spotify
        </a>
    `;
}

// Show Spotify login prompt
function showSpotifyLoginPrompt() {
    const playlistDisplay = document.getElementById('playlistDisplay');
    playlistDisplay.innerHTML = `
        <div class="spotify-login-prompt">
            <p>Connect with Spotify to generate mood-based playlists!</p>
            <button onclick="handleSpotifyLogin()" class="spotify-login-btn glass-card">
                Connect with Spotify
            </button>
        </div>
    `;
}

// Show error message
function showError(message) {
    const playlistDisplay = document.getElementById('playlistDisplay');
    playlistDisplay.innerHTML = `
        <div class="error-message">
            <p>${message}</p>
        </div>
    `;
}

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', initSpotify); 