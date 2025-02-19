# Hobbymouse 40k League Tracker

## A Python-based web application for managing competitive Warhammer 40k league and tournament play. 

### Features

#### League Play
- **Match Submission:**
  - Players submit match results, including army and detachment data.
  - Scoring:
    - Win: 3 points
    - Draw: 2 points
    - Loss: 1 point
    - New Opponent Bonus: 1 extra point (first meeting)
    - Registration Bonus: 1 extra point (one-time)
  - Max two league games per week (no repeat opponents in the same week) at Rhostio Specialist Coffee.
- **League Table:**
  - Displays detailed standings with profile pictures, number of matches, wins, draws, losses, and win rate.
  - Usernames link to match history.

#### Tournament Events
- **Event Management:**
  - Admins create events with custom round settings.
- **Participant Management:**
  - Admins add/remove participants.
- **Tournament Rounds:**
  - Auto-generates initial pairings.
  - Admins submit scores and generate next-round pairings.
  - Final round determines the champion.

#### User Management
- **Registration & Login:**
  - Users register with a unique username.
  - Random password generated and displayed once.
- **Profile Management:**
  - Users update profiles and upload pictures (rescaled to 480px height).
- **Match History:**
  - Users view match history, broken down by event.

#### Admin Portal
- **User Administration:**
  - Create/edit users, reset passwords.
- **Match Administration:**
  - Edit/delete match submissions.
- **Event Administration:**
  - Manage events, rounds, scores, and view stats.

#### Frontend & Styling
- Bootstrap 5 for modern, responsive design.
- Custom CSS enhancements.
- Pagination for matches and events.

### Project Structure
```
warhammer_league_app/
├── app.py
├── requirements.txt
├── migrations/         # Flask-Migrate (Alembic)
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── new_match.html
│   ├── user_history.html
│   ├── admin_dashboard.html
│   ├── admin_create_user.html
│   ├── admin_edit_user.html
│   ├── admin_edit_match.html
│   ├── admin_create_event.html
│   ├── admin_add_event_participants.html
│   ├── admin_tournament_round.html
│   └── event_detail.html
└── static/
    ├── css/
    │   └── style.css
    ├── img/
    │   └── generic.png
    └── profile_pics/
```

### Local Development
```bash
git clone <your-repository-url>
cd warhammer_league_app
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
flask db init  # if not already initialised
flask db migrate -m "Initial migration"
flask db upgrade
python -m flask run
```

### Deployment & Updating on PythonAnywhere
#### Update Your Code Repository
```bash
git add .
git commit -m "Update for tournament, league table enhancements and pagination"
git push origin main
```
#### Log in to PythonAnywhere
- Go to the PythonAnywhere Dashboard.
- Update Your Web App Source:
  - Navigate to the "Web" tab.
  - Click on "Pull latest code" or update via Git.
  - Confirm updates (check app.py, templates, etc.).

#### Update Database Migrations on PythonAnywhere
```bash
flask db migrate -m "Update for tournament event management and pagination"
flask db upgrade
```
#### Reload Your Web App
- Go to the "Web" tab.
- Click "Reload" to restart your app.
- Test the application to confirm updates.

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
