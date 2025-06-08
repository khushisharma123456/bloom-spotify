from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from urllib.parse import unquote
import os
import json
import requests
from urllib.parse import urlencode
import base64
from datetime import datetime, timedelta


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

SPOTIFY_CLIENT_ID = 'abc5d2ee561440dda30db22c9a21de11'
SPOTIFY_CLIENT_SECRET = '76df013118044b8abd348bf963c65d55'
SPOTIFY_REDIRECT_URI = 'https://bloom-spotify.onrender.com/callback'
SPOTIFY_AUTH_URL = 'https://accounts.spotify.com/authorize'
SPOTIFY_TOKEN_URL = 'https://accounts.spotify.com/api/token'
SPOTIFY_API_BASE = 'https://api.spotify.com/v1'

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    survey_completed = db.Column(db.Boolean, default=False)
    cycle_length = db.Column(db.Integer, default=28)  # Added to store user's cycle length
    period_length = db.Column(db.Integer, default=5)  # Added to store user's period length

    # Relationship to track history
    entries = db.relationship('PainEntry', backref='user', lazy=True)

class PainEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    pain_level = db.Column(db.String(20))
    flow_level = db.Column(db.String(20))
    mood = db.Column(db.String(20))
    symptoms = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class SurveyResponse(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    q1_age = db.Column(db.Integer)
    q2_last_period = db.Column(db.Date)
    q3_period_duration = db.Column(db.String(30))
    q4_cycle_length = db.Column(db.String(30))
    q5_period_regularity = db.Column(db.String(30))
    q6_hair_growth = db.Column(db.String(10))
    q7_acne = db.Column(db.String(10))
    q8_hair_thinning = db.Column(db.String(10))
    q9_weight_gain = db.Column(db.String(30))
    q10_sugar_craving = db.Column(db.String(10))
    q11_family_history = db.Column(db.String(30))
    q12_fertility = db.Column(db.String(30))
    q13_mood_swings = db.Column(db.String(30))

with app.app_context():
    db.create_all()

    
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.full_name
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        is_new_signup = 'is_new_signup' in request.form  # Check for new signup

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(full_name=full_name, email=email, password=hashed_password, survey_completed=False)

        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Log the user in automatically
            session['user_id'] = new_user.id
            session['user_name'] = new_user.full_name
            
            # Redirect to survey for new signups, dashboard otherwise
            if is_new_signup:
                flash('Account created! Please complete our quick survey.', 'success')
                return redirect(url_for('survey'))
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('Email already registered!', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/survey', methods=['GET', 'POST'])
def survey():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Get the date string from the form (format: "d MMM yyyy" like "15 Jun 2023")
            last_period_str = request.form.get('q2')
            
            # Parse the date string into a date object
            try:
                last_period = datetime.strptime(last_period_str, '%d %b %Y').date()
            except ValueError:
                # Try alternative format if the first one fails
                try:
                    last_period = datetime.strptime(last_period_str, '%Y-%m-%d').date()
                except ValueError as e:
                    flash(f'Invalid date format: {last_period_str}. Please use the calendar picker.', 'danger')
                    return redirect(url_for('survey'))

            # Debug print all form data
            print("Form data received:", request.form)
            
            new_response = SurveyResponse(
                user_id=session['user_id'],
                q1_age=request.form.get('q1', type=int),
                q2_last_period=last_period,
                q3_period_duration=request.form.get('q3'),
                q4_cycle_length=request.form.get('q4'),
                q5_period_regularity=request.form.get('q5'),
                q6_hair_growth=request.form.get('q6'),
                q7_acne=request.form.get('q7'),
                q8_hair_thinning=request.form.get('q8'),
                q9_weight_gain=request.form.get('q9'),
                q10_sugar_craving=request.form.get('q10'),
                q11_family_history=request.form.get('q11'),
                q12_fertility=request.form.get('q12'),
                q13_mood_swings=request.form.get('q13')
            )

            user.survey_completed = True
            db.session.add(new_response)
            db.session.commit()

            flash('Thank you for completing the survey!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error saving survey responses: {str(e)}. Please check all fields and try again.', 'danger')
            print("Error details:", str(e))
            return redirect(url_for('survey'))
    
    return render_template('survey.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if not user.survey_completed:
        flash('Please complete the survey first!', 'warning')
        return redirect(url_for('survey'))

    # ⬇️ Fetch latest survey response
    survey = SurveyResponse.query.filter_by(user_id=user.id).order_by(SurveyResponse.timestamp.desc()).first()

    if not survey or not survey.q2_last_period:
        flash('Survey data is missing or incomplete.', 'warning')
        return redirect(url_for('survey'))

    # Calculate cycle day and phase
    today = datetime.utcnow().date()
    days_since_period = (today - survey.q2_last_period).days
    current_day = (days_since_period % user.cycle_length) + 1 if days_since_period >= 0 else 0

    if current_day <= user.period_length:
        current_phase = "Menstrual"
    elif current_day <= (user.cycle_length - 14):
        current_phase = "Follicular"
    elif current_day <= (user.cycle_length - 9):
        current_phase = "Ovulation"
    else:
        current_phase = "Luteal"

    return render_template(
        'index.html',
        user_name=session['user_name'],
        current_day=current_day,
        current_phase=current_phase,
        cycle_length=user.cycle_length,
        period_length=user.period_length
    )

    
# Period Tracker Page (Only for logged-in users)
pain_mapping = {'No Pain': 0, 'Mild': 3, 'Moderate': 5, 'Severe': 10}
flow_mapping = {'None': 0, 'Light': 2, 'Medium': 5, 'Heavy': 8}

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime, timedelta
import os
import json

try:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "menstrualcyclelen.json")
    print("Loading JSON from:", json_path)

    with open(json_path, "r") as f:
        data = json.load(f)
except FileNotFoundError as e:
    print("File not found:", e)
    data = {}  # Or maybe you want to crash intentionally with raise e
except Exception as e:
    print("Unexpected error loading JSON:", e)
    data = {}


# ------------------------ Helper: Predict Cycle ------------------------
def predict_cycle(start_date_str, cycle_length):
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
    next_period = start_date + timedelta(days=cycle_length)
    ovulation_start = next_period - timedelta(days=14)
    ovulation_end = ovulation_start + timedelta(days=5)

    return {
        "next_period": next_period.strftime("%Y-%m-%d"),
        "ovulation_window": [
            ovulation_start.strftime("%Y-%m-%d"),
            ovulation_end.strftime("%Y-%m-%d")
        ]
    }

# ------------------------ Main Route ------------------------
from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime, timedelta


@app.route('/period_tracker', methods=['GET', 'POST'])
def period_tracker():
    if request.method == 'POST':
        start_date_str = request.form.get('start_date')  # This should now be a valid string
        if not start_date_str:
            return "Start date is required", 400

        # Convert string to datetime object
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')

        # Get other form data
        flow = request.form.get('flow')
        symptoms = request.form.getlist('symptoms')
        emotions = request.form.getlist('emotions')
        notes = request.form.get('notes')

        # Calculate next period date (example logic: 28-day cycle)
        next_period_date = start_date + timedelta(days=28)

        return render_template('tracker_result.html',
                               start_date=start_date_str,
                               next_period_date=next_period_date.strftime('%Y-%m-%d'),
                               flow=flow,
                               symptoms=symptoms,
                               emotions=emotions,
                               notes=notes)

    return render_template('period_tracker.html')


# ------------------------ Separate API Route (Optional) ------------------------
@app.route('/predict_cycle', methods=['POST'])
def cycle_predict():
    start_date = request.form['start_date']
    cycle_length = int(request.form['cycle_length'])
    prediction = predict_cycle(start_date, cycle_length)
    return jsonify(prediction)


@app.route('/nutrition')
def nutrition():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('Nutrition.html')


@app.route('/index')
def index():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('index (1).html')

@app.route('/about')
def about():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('about.html')



@app.route('/yoga')
def yoga():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('yoga.html', user_name=session['user_name'])

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('admin.html', user_name=session['user_name'])

@app.route('/consultation')
def consultation():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('consultation.html', user_name=session['user_name'])

#===========================================================================================================


@app.route('/mood')
def mood():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('mood.html', user_name=session['user_name'])

# Add this function to check Spotify token status
def is_spotify_token_valid():
    if 'spotify_token_expiry' not in session:
        return False
    return datetime.now() < session['spotify_token_expiry']

# Update the spotify_login route
@app.route('/spotify_login')
def spotify_login():
    """Redirect user to Spotify authorization page"""
    scope = 'user-read-private user-read-email playlist-read-private playlist-modify-public playlist-modify-private'
    
    params = {
        'client_id': SPOTIFY_CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': SPOTIFY_REDIRECT_URI,
        'scope': scope,
        'show_dialog': True
    }
    
    auth_url = f"{SPOTIFY_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

# Update the callback route with better error handling
@app.route('/callback')
def spotify_callback():
    if 'error' in request.args:
        error = request.args.get('error')
        flash(f'Spotify authorization failed: {error}', 'error')
        return redirect(url_for('dashboard'))
    
    if 'code' not in request.args:
        flash('Authorization code not received from Spotify', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        code = request.args['code']
        
        # Prepare the authorization header
        auth_header = base64.b64encode(
            f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()
        ).decode()
        
        headers = {
            'Authorization': f'Basic {auth_header}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Exchange code for access token
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': SPOTIFY_REDIRECT_URI,
        }
        
        auth_response = requests.post(SPOTIFY_TOKEN_URL, data=token_data, headers=headers)
        auth_response.raise_for_status()
        
        auth_data = auth_response.json()
        
        # Store tokens in session with expiry time
        session['spotify_access_token'] = auth_data['access_token']
        if 'refresh_token' in auth_data:
            session['spotify_refresh_token'] = auth_data['refresh_token']
        
        # Set token expiry time (1 hour from now)
        session['spotify_token_expiry'] = datetime.now() + timedelta(seconds=auth_data.get('expires_in', 3600))
        
        # Get user profile to store display name
        profile_headers = {
            'Authorization': f"Bearer {auth_data['access_token']}"
        }
        profile_response = requests.get(f"{SPOTIFY_API_BASE}/me", headers=profile_headers)
        profile_response.raise_for_status()
        
        profile_data = profile_response.json()
        session['spotify_display_name'] = profile_data.get('display_name', 'Spotify User')
        session['spotify_user_id'] = profile_data.get('id')
        
        flash('Successfully connected with Spotify!', 'success')
        return redirect(url_for('dashboard'))
    
    except requests.exceptions.RequestException as e:
        flash(f'Failed to connect with Spotify: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Unexpected error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# Update the refresh token route
@app.route('/refresh_token')
def refresh_token():
    if 'spotify_refresh_token' not in session:
        return jsonify({"error": "No refresh token"}), 401
    
    # Prepare the authorization header
    auth_header = base64.b64encode(
        f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()
    ).decode()
    
    headers = {
        'Authorization': f'Basic {auth_header}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    refresh_response = requests.post(SPOTIFY_TOKEN_URL, data={
        'grant_type': 'refresh_token',
        'refresh_token': session['spotify_refresh_token'],
    }, headers=headers)
    
    if refresh_response.status_code == 200:
        refresh_data = refresh_response.json()
        session['spotify_access_token'] = refresh_data['access_token']
        session['spotify_token_expiry'] = datetime.now() + timedelta(seconds=refresh_data.get('expires_in', 3600))
        
        # Spotify may not return a new refresh token, so we keep the existing one
        if 'refresh_token' in refresh_data:
            session['spotify_refresh_token'] = refresh_data['refresh_token']
        
        return jsonify({"access_token": refresh_data['access_token']})
    else:
        return jsonify({"error": "Failed to refresh token"}), 400

# Update the get_mood_playlist route in app.py
# Update the get_mood_playlist route in app.py
@app.route('/get_mood_playlist', methods=['POST'])
def get_mood_playlist():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 401
    
    # Check Spotify token status
    if not is_spotify_token_valid():
        if 'spotify_refresh_token' in session:
            refresh_response = refresh_token()
            if refresh_response.status_code != 200:
                return jsonify({'error': 'Spotify session expired. Please reconnect.'}), 401
        else:
            return jsonify({'error': 'Spotify not connected'}), 401
    
    data = request.get_json()
    mood = data.get('mood')
    intensity = data.get('intensity', 3)
    
    if not mood:
        return jsonify({'error': 'Mood not specified'}), 400
    
    # Enhanced mood to playlist mapping with mood improvement paths
    mood_playlists = {
        'happy': {
            1: {'id': '37i9dQZF1DXdPec7aLTmlC', 'name': 'Happy Hits', 'description': 'Light and cheerful tunes to maintain your happiness'},
            2: {'id': '37i9dQZF1DX3rxVfibe1L0', 'name': 'Mood Booster', 'description': 'Songs scientifically proven to boost your mood'},
            3: {'id': '37i9dQZF1DX0XUsuxWHRQd', 'name': 'RapCaviar', 'description': 'High-energy hip-hop to keep your spirits high'},
            4: {'id': '37i9dQZF1DX4dyzvuaRJ0n', 'name': 'mint', 'description': 'Fresh dance and electronic music to elevate your mood'},
            5: {'id': '37i9dQZF1DX4SBhb3fqCJd', 'name': 'Are & Be', 'description': 'The best in uplifting R&B right now'}
        },
        'sad': {
            1: {'id': '37i9dQZF1DX7qK8ma5wgG1', 'name': 'Comforting Melodies', 'description': 'Gentle songs to comfort you in tough times'},
            2: {'id': '37i9dQZF1DWVV27DiNWxkR', 'name': 'Indie Comfort', 'description': 'Indie songs that understand what you\'re feeling'},
            3: {'id': '37i9dQZF1DX3YSRoSdA634', 'name': 'Life Sucks', 'description': 'Songs that get it when you\'re feeling down'},
            4: {'id': '37i9dQZF1DX1s9knjP51Oa', 'name': 'Calm Vibes', 'description': 'Soothing music to help you relax and recover'},
            5: {'id': '37i9dQZF1DX3rxVfibe1L0', 'name': 'Mood Booster', 'description': 'Songs to help lift you out of sadness'}
        },
        'angry': {
            1: {'id': '37i9dQZF1DX0vHZ8elq0UK', 'name': 'Rock This', 'description': 'Classic rock anthems to channel your energy'},
            2: {'id': '37i9dQZF1DX1s9knjP51Oa', 'name': 'Calm Vibes', 'description': 'Soothing instrumental music to calm your mind'},
            3: {'id': '37i9dQZF1DX4sWSpwq3LiO', 'name': 'Rock Classics', 'description': 'Legendary rock tracks to help you release tension'},
            4: {'id': '37i9dQZF1DWU0ScTcjJBdj', 'name': 'Relax & Unwind', 'description': 'Music to help you relax and let go of anger'},
            5: {'id': '37i9dQZF1DX5wgkQjaJeZO', 'name': 'Thrash Metal', 'description': 'High-intensity metal for when you need to vent'}
        },
        'energetic': {
            1: {'id': '37i9dQZF1DX9tPFwDMOaN1', 'name': 'Energy Booster', 'description': 'Upbeat tracks to get you moving'},
            2: {'id': '37i9dQZF1DX76Wlfdnj7AP', 'name': 'Beast Mode', 'description': 'High-energy workout music'},
            3: {'id': '37i9dQZF1DX0XUsuxWHRQd', 'name': 'RapCaviar', 'description': 'The hottest hip-hop tracks'},
            4: {'id': '37i9dQZF1DX8f6LHxMjnzD', 'name': 'Punk Rock', 'description': 'Fast and furious punk anthems'},
            5: {'id': '37i9dQZF1DXa2SPUyWl8Y5', 'name': 'Cardio', 'description': 'High-energy tracks to keep you pumped'}
        },
        'content': {
            1: {'id': '37i9dQZF1DX4WYpdgoIcn6', 'name': 'Chill Hits', 'description': 'Relaxed vibes for easy listening'},
            2: {'id': '37i9dQZF1DX7qK8ma5wgG1', 'name': 'Peaceful Piano', 'description': 'Calming piano music for relaxation'},
            3: {'id': '37i9dQZF1DWU0ScTcjJBdj', 'name': 'Relax & Unwind', 'description': 'Soothing sounds to calm your mind'},
            4: {'id': '37i9dQZF1DX4WYpdgoIcn6', 'name': 'Chill Hits', 'description': 'Relaxed vibes for easy listening'},
            5: {'id': '37i9dQZF1DX4WYpdgoIcn6', 'name': 'Chill Hits', 'description': 'Relaxed vibes for easy listening'}
        }
    }
    
    # If mood is negative (sad/angry), consider suggesting a path to better mood
    if mood.lower() == 'sad' and intensity >= 4:
        # For high-intensity sadness, suggest happy playlists
        playlist_info = mood_playlists['happy'].get(3)  # Default to medium happy
    elif mood.lower() == 'angry' and intensity >= 4:
        # For high-intensity anger, suggest calming playlists
        playlist_info = mood_playlists['content'].get(2)  # Default to medium calm
    else:
        # Otherwise use the requested mood
        playlist_info = mood_playlists.get(mood.lower(), {}).get(int(intensity), None)
    
    if not playlist_info:
        return jsonify({'error': 'No playlist found for this mood'}), 404
    
    # Get playlist details from Spotify
    headers = {
        'Authorization': f"Bearer {session['spotify_access_token']}"
    }
    
    try:
        # Get playlist details
        playlist_url = f"{SPOTIFY_API_BASE}/playlists/{playlist_info['id']}"
        response = requests.get(playlist_url, headers=headers)
        
        if response.status_code != 200:
            return jsonify({'error': 'Failed to get playlist from Spotify'}), 500
        
        playlist_data = response.json()
        
        # Get a few sample tracks
        tracks_url = f"{SPOTIFY_API_BASE}/playlists/{playlist_info['id']}/tracks?limit=5"
        tracks_response = requests.get(tracks_url, headers=headers)
        tracks_data = tracks_response.json() if tracks_response.status_code == 200 else {'items': []}
        
        sample_tracks = []
        for item in tracks_data.get('items', [])[:3]:
            track = item.get('track', {})
            artists = ", ".join([artist['name'] for artist in track.get('artists', [])])
            sample_tracks.append({
                'name': track.get('name', 'Unknown Track'),
                'artists': artists,
                'preview_url': track.get('preview_url')
            })
        
        return jsonify({
            'playlist_id': playlist_info['id'],
            'playlist_name': playlist_info['name'],
            'playlist_description': playlist_info['description'],
            'playlist_url': playlist_data.get('external_urls', {}).get('spotify', ''),
            'playlist_image': playlist_data.get('images', [{}])[0].get('url', ''),
            'tracks': playlist_data.get('tracks', {}).get('total', 0),
            'sample_tracks': sample_tracks,
            'owner': playlist_data.get('owner', {}).get('display_name', 'Spotify'),
            'original_mood': mood,
            'original_intensity': intensity
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add this route to check Spotify connection status
@app.route('/check_spotify_status')
def check_spotify_status():
    try:
        # Check if we have a valid token
        if 'spotify_access_token' not in session:
            return jsonify({'connected': False})
            
        # Verify token is still valid
        headers = {
            'Authorization': f"Bearer {session['spotify_access_token']}"
        }
        response = requests.get(f"{SPOTIFY_API_BASE}/me", headers=headers)
        
        if response.status_code == 200:
            profile = response.json()
            return jsonify({
                'connected': True,
                'display_name': profile.get('display_name', 'Spotify User')
            })
        
        # If token is invalid, clear session
        session.pop('spotify_access_token', None)
        return jsonify({'connected': False})
        
    except requests.exceptions.RequestException as e:
        return jsonify({
            'error': f"Network error: {str(e)}"
        }), 500
    except Exception as e:
        return jsonify({
            'error': f"Unexpected error: {str(e)}"
        }), 500
#=======================================================================================================================



@app.route('/chatbot')
def chatbot():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    return render_template('chatbot.html')

@app.route('/api/get-api-key')
def get_api_key():
    print("GEMINI KEY:", os.getenv("GEMINI_API_KEY"))
    api_key = os.getenv('GEMINI_API_KEY')
    print("DEBUG: Loaded API Key =", api_key)  # Add this for verification
    if not api_key:
        abort(500, description="API key not configured on server")
    return jsonify({'apiKey': api_key})

    
@app.route('/api/get-prompt-template')
def get_prompt_template():
    try:
        with open('templates/prompt_template.txt', 'r') as file:
            return file.read()
    except FileNotFoundError:
        abort(404, description="Prompt template not found")
    except Exception as e:
        abort(500, description=str(e))
        
@app.route('/settings')
def settings():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    survey = SurveyResponse.query.filter_by(user_id=user.id).order_by(SurveyResponse.timestamp.desc()).first()
    
    return render_template('settings.html', 
                         user_name=user.full_name,
                         email=user.email,
                         cycle_length=user.cycle_length,
                         period_length=user.period_length,
                         survey=survey)

# Add these new routes to app.py

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        user.full_name = request.form.get('full_name', user.full_name)
        db.session.commit()
        session['user_name'] = user.full_name  # Update session name
        return jsonify({'success': True, 'message': 'Profile updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/update_cycle_settings', methods=['POST'])
def update_cycle_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        cycle_length = request.form.get('cycle_length', type=int)
        period_length = request.form.get('period_length', type=int)
        
        if cycle_length and 20 <= cycle_length <= 45:  # Validate reasonable range
            user.cycle_length = cycle_length
        if period_length and 1 <= period_length <= 14:  # Validate reasonable range
            user.period_length = period_length
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'Cycle settings updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/update_period_dates', methods=['POST'])
def update_period_dates():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        
        # Find or create a survey response for this user
        survey = SurveyResponse.query.filter_by(user_id=session['user_id']).order_by(SurveyResponse.timestamp.desc()).first()
        if not survey:
            survey = SurveyResponse(user_id=session['user_id'])
            db.session.add(survey)
        
        survey.q2_last_period = start_date
        survey.q3_period_duration = f"{(end_date - start_date).days + 1} days"
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Period dates updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/get_user_settings')
def get_user_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    survey = SurveyResponse.query.filter_by(user_id=user.id).order_by(SurveyResponse.timestamp.desc()).first()
    
    return jsonify({
        'full_name': user.full_name,
        'email': user.email,
        'cycle_length': user.cycle_length,
        'period_length': user.period_length,
        'last_period': survey.q2_last_period.strftime('%Y-%m-%d') if survey and survey.q2_last_period else None,
        'period_duration': survey.q3_period_duration if survey else None,
        'cycle_regularity': survey.q5_period_regularity if survey else None,
        'symptoms': survey.q13_mood_swings if survey else None,
        'hormonal_conditions': survey.q11_family_history if survey else None  # Using this field as example
    })
    
@app.route('/update_survey_answers', methods=['POST'])
def update_survey_answers():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        survey = SurveyResponse.query.filter_by(user_id=user.id).order_by(SurveyResponse.timestamp.desc()).first()
        if not survey:
            survey = SurveyResponse(user_id=user.id)
            db.session.add(survey)
        
        # Update fields based on form data
        if 'cycle_regularity' in request.form:
            survey.q5_period_regularity = request.form['cycle_regularity']
        
        if 'cycle_length' in request.form:
            try:
                cycle_length = int(request.form['cycle_length'])
                if 20 <= cycle_length <= 45:  # Validate range
                    user.cycle_length = cycle_length
                else:
                    return jsonify({'error': 'Cycle length must be between 20-45 days'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid cycle length'}), 400
        
        if 'symptoms' in request.form:
            survey.q13_mood_swings = request.form['symptoms']
        
        if 'hormonal_conditions' in request.form:
            # Add this field to your SurveyResponse model if needed
            pass
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Survey answers updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e), 'message': 'Failed to save changes'}), 500

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

#=====================================================================================
def load_recipes():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(base_dir, 'data', 'recipes.json')
        
        with open(json_path) as f:
            data = json.load(f)
            return {recipe['title'].lower(): recipe for recipe in data['recipes']}
    except Exception as e:
        print(f"Error loading recipes: {str(e)}")
        return {}

recipes = load_recipes()

@app.route('/remedy/<path:remedy_name>')
def remedy_details(remedy_name):
    print(f"\n\n=== DEBUG: Received request for: {remedy_name} ===")  # Check terminal
    decoded_name = unquote(remedy_name).lower()
    print(f"Decoded name: {decoded_name}")
    
    recipe = recipes.get(decoded_name)
    if not recipe:
        recipe = recipes.get(remedy_name.replace('-', ' ').lower())
    
    if not recipe:
        print("Recipe not found!")
        abort(404)
    
    print(f"Found recipe: {recipe['title']}")  # Verify match
    return render_template('remedy.html', remedy=recipe)


            
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
