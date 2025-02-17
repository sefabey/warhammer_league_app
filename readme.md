# Hobbymouse 40k League Tracker

This is a Python-based web application for tracking competitive Warhammer 40k league matches for Hobbymouse. It allows players to submit match results, track league standings, and view detailed profiles and match history.

## League Rules
1. Each player can play two league games per week, not facing the same opponent in the same week, only at Rhostio Specialist Coffee.
2. Each list must be 2000 points, following standard matched play rules.
3. Missions come from the Pariah Nexus Deck, or if both players agree, use UKTC/WTC.
4. Bonus: 1 extra point is awarded for playing a new opponent (if the matchup is a first-time meeting).
5. Additionally, 1 extra point is awarded for registering (granted once, after the first game).
6. Scores must be recorded on the league tracker before leaving the premises.

## Features
- **Match Submission:** Users can select a match date (which may differ from the submission date), choose army names, and input scores.
- **Automatic New Opponent Bonus:** The system automatically deduces if the matchup is a first-time meeting and awards bonus points accordingly.
- **User Profiles:** Click on a username to view a detailed profile with a rescaled profile picture (480px in height) and match statistics.
- **Admin Portal:** Admin users can log in via a dedicated admin login page to manage users and reset passwords.
- **Match History:** Detailed match history includes match dates, scores, and army names for both players.

## Project Structure
```
project/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── admin_login.html
│   ├── profile.html
│   ├── new_match.html
│   ├── user_history.html
│   └── admin_dashboard.html
└── static/
    └── profile_pics/  # For user profile pictures
```

## Local Development

### Using Conda
1. Create a new Conda environment:
   ```bash
   conda create -n league_tracker python=3.10
   conda activate league_tracker
   ```
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   export FLASK_APP=app.py
   python -m flask run
   ```

### Using venv
1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   export FLASK_APP=app.py
   python -m flask run
   ```

## Deployment
This application can be deployed on platforms such as Render, Heroku, or PythonAnywhere.

### Example for Heroku
1. Create a `Procfile` with the following content:
   ```
   web: gunicorn app:app
   ```
2. Ensure that `gunicorn` is added to your `requirements.txt`.
3. Commit your code and push to Heroku following their deployment instructions.

## Embedding in Fourthwall
Once deployed, obtain your application URL. To embed in Fourthwall, use an iframe similar to:

```html
<iframe src="https://your-deployed-app-url.com" width="100%" height="600" frameborder="0"></iframe>
```

## Notes
- All text in this application uses British English.
- Profile pictures are automatically rescaled to a height of 480 pixels upon upload.
- The league rules are reiterated above for clarity.

