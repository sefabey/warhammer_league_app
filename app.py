from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from passlib.hash import pbkdf2_sha256
import secrets, os, random
from datetime import datetime
from PIL import Image
from flask_migrate import Migrate

# --------------------
# Configuration
# --------------------
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///league.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'profile_pics')
    SESSION_COOKIE_SAMESITE = 'None'
    SESSION_COOKIE_SECURE = True
    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --------------------
# Models
# --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    registration_bonus = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(120), nullable=True)

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

# Association table for event participants
event_participants = db.Table('event_participants',
    db.Column('event_id', db.Integer, db.ForeignKey('event.id', name='fk_event_participants_event'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', name='fk_event_participants_user'), primary_key=True)
)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    event_date = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(20))  # 'league' or 'tournament'
    description = db.Column(db.Text, nullable=True)
    is_finished = db.Column(db.Boolean, default=False)
    num_rounds = db.Column(db.Integer, default=3)  # For tournaments
    current_round = db.Column(db.Integer, default=1)
    champion_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    matches = db.relationship('Match', backref='event', lazy=True)
    participants = db.relationship('User', secondary=event_participants, backref='events')

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    player1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    player2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    player1_army = db.Column(db.String(80))
    player2_army = db.Column(db.String(80))
    player1_detachment = db.Column(db.String(80), nullable=True)
    player2_detachment = db.Column(db.String(80), nullable=True)
    player1_score = db.Column(db.Integer, nullable=False)
    player2_score = db.Column(db.Integer, nullable=False)
    player1_new_opponent = db.Column(db.Boolean, default=False)
    player2_new_opponent = db.Column(db.Boolean, default=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id', name='fk_match_event'), nullable=True)
    round_number = db.Column(db.Integer, nullable=True)

    player1 = db.relationship('User', foreign_keys=[player1_id], backref='matches_as_player1')
    player2 = db.relationship('User', foreign_keys=[player2_id], backref='matches_as_player2')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.before_first_request
def create_tables():
    with app.app_context():
        db.create_all()


# --------------------
# Helper Functions
# --------------------
def get_tournament_stats(user, event):
    """
    Calculate tournament statistics for a given user in the event.
    Only count matches that have been played (i.e. where at least one score is nonzero).
    Returns a tuple: (points, wins, draws, losses)
    """
    matches = Match.query.filter_by(event_id=event.id).filter(
        ((Match.player1_id == user.id) | (Match.player2_id == user.id))
    ).all()
    points = wins = draws = losses = 0
    for m in matches:
        # Skip unplayed matches (both scores are 0)
        if m.player1_score == 0 and m.player2_score == 0:
            continue
        if m.player1_id == user.id:
            score = m.player1_score
            opp_score = m.player2_score
        else:
            score = m.player2_score
            opp_score = m.player1_score
        if score > opp_score:
            wins += 1
            points += 3
        elif score < opp_score:
            losses += 1
            points += 1
        else:
            draws += 1
            points += 2
    return points, wins, draws, losses

def get_tournament_score(user, event):
    pts, _, _, _ = get_tournament_stats(user, event)
    return pts
# --------------------
# Routes
# --------------------

@app.route('/')
def index():
    # Get current page number (default=1)
    page = request.args.get('page', 1, type=int)
    # League matches: those without an event.
    pagination = Match.query.filter(Match.event_id.is_(None)) \
        .order_by(Match.submission_date.desc()) \
        .paginate(page=page, per_page=6, error_out=False)
    league_matches = pagination.items

    users = User.query.all()
    stats = {}
    for user in users:
        stats[user.id] = {
            'id': user.id,
            'username': user.username,
            'points': 0,
            'matches': 0,
            'wins': 0,
            'draws': 0,
            'losses': 0,
            'profile_picture': user.profile_picture
        }
    for match in Match.query.filter(Match.event_id.is_(None)).all():
        if match.player1_score > match.player2_score:
            p1_points = 3
            p2_points = 1
        elif match.player1_score < match.player2_score:
            p1_points = 1
            p2_points = 3
        else:
            p1_points = 2
            p2_points = 2
        if match.player1_new_opponent:
            p1_points += 1
        if match.player2_new_opponent:
            p2_points += 1
        stats[match.player1_id]['points'] += p1_points
        stats[match.player1_id]['matches'] += 1
        stats[match.player2_id]['points'] += p2_points
        stats[match.player2_id]['matches'] += 1
        if match.player1_score > match.player2_score:
            stats[match.player1_id]['wins'] += 1
            stats[match.player2_id]['losses'] += 1
        elif match.player1_score < match.player2_score:
            stats[match.player1_id]['losses'] += 1
            stats[match.player2_id]['wins'] += 1
        else:
            stats[match.player1_id]['draws'] += 1
            stats[match.player2_id]['draws'] += 1
    for uid, data in stats.items():
        total = data['matches']
        data['win_rate'] = (data['wins'] / total * 100) if total > 0 else 0
    league_table = list(stats.values())
    league_table.sort(key=lambda x: x['points'], reverse=True)

    finished_events = Event.query.filter_by(is_finished=True).order_by(Event.event_date.desc()).all()
    ongoing_events = Event.query.filter_by(is_finished=False).order_by(Event.event_date.desc()).all()

    return render_template('index.html', league_matches=league_matches, pagination=pagination,
                           league_table=league_table, finished_events=finished_events, ongoing_events=ongoing_events)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        random_password = secrets.token_urlsafe(8)
        new_user = User(username=username)
        new_user.set_password(random_password)
        if User.query.first() is None:
            new_user.is_admin = True
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"New user registered: {username}, password: {random_password}")
        flash(f'Your account has been created. Your password is: {random_password} (Please note it down, it will only be shown once)', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_admin:
            login_user(user)
            flash('Admin logged in successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials.', 'danger')
        return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            current_user.username = username
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename != '':
                filename = f'user_{current_user.id}_{file.filename}'
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                try:
                    img = Image.open(filepath)
                    w, h = img.size
                    new_height = 480
                    new_width = int(w * (new_height / h))
                    img = img.resize((new_width, new_height), resample=Image.LANCZOS)
                    img.save(filepath)
                except Exception as e:
                    flash(f'Error processing image: {e}', 'danger')
                    return redirect(url_for('profile'))
                current_user.profile_picture = filename
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/match/new', methods=['GET', 'POST'])
@login_required
def new_match():
    active_events = Event.query.filter_by(is_finished=False).all()
    users = User.query.all()
    if request.method == 'POST':
        player1_id = int(request.form.get('player1'))
        player2_id = int(request.form.get('player2'))
        if player1_id == player2_id:
            flash('A match must be between two different players.', 'danger')
            return redirect(url_for('new_match'))

        match_date_str = request.form.get('match_date')
        try:
            match_date = datetime.fromisoformat(match_date_str) if match_date_str else datetime.utcnow()
        except ValueError:
            flash('Invalid match date format.', 'danger')
            return redirect(url_for('new_match'))

        player1_army = request.form.get('player1_army')
        player2_army = request.form.get('player2_army')
        player1_detachment = request.form.get('player1_detachment')
        player2_detachment = request.form.get('player2_detachment')
        try:
            player1_score = int(request.form.get('player1_score'))
            player2_score = int(request.form.get('player2_score'))
        except ValueError:
            flash('Scores must be integers.', 'danger')
            return redirect(url_for('new_match'))

        event_id = request.form.get('event_id')
        event_id = int(event_id) if event_id else None

        existing_match = Match.query.filter(
            ((Match.player1_id == player1_id) & (Match.player2_id == player2_id)) |
            ((Match.player1_id == player2_id) & (Match.player2_id == player1_id))
        ).first()
        new_bonus1 = new_bonus2 = not bool(existing_match)

        match = Match(
            match_date=match_date,
            player1_id=player1_id,
            player2_id=player2_id,
            player1_army=player1_army,
            player2_army=player2_army,
            player1_detachment=player1_detachment,
            player2_detachment=player2_detachment,
            player1_score=player1_score,
            player2_score=player2_score,
            player1_new_opponent=new_bonus1,
            player2_new_opponent=new_bonus2,
            event_id=event_id
        )
        db.session.add(match)
        db.session.commit()

        for uid in [player1_id, player2_id]:
            user = User.query.get(uid)
            if not user.registration_bonus:
                user.registration_bonus = True
        db.session.commit()

        flash('Match recorded successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('new_match.html', users=users, active_events=active_events)

@app.route('/admin/delete_match/<int:match_id>', methods=['POST'])
@login_required
def delete_match(match_id):
    if not current_user.is_admin:
        abort(403)
    match = Match.query.get_or_404(match_id)
    db.session.delete(match)
    db.session.commit()
    flash('Match deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# @app.route('/user/<int:user_id>')
# def user_history(user_id):
#     user = User.query.get_or_404(user_id)
#     league_matches = Match.query.filter(
#         ((Match.player1_id == user.id) | (Match.player2_id == user.id)) &
#         (Match.event_id.is_(None))
#     ).all()
#     league_matches.sort(key=lambda m: m.submission_date, reverse=True)

#     total_matches = len(league_matches)
#     wins = draws = losses = total_points = 0
#     for m in league_matches:
#         if m.player1_id == user.id:
#             score = m.player1_score
#             opp_score = m.player2_score
#             bonus = 1 if m.player1_new_opponent else 0
#         else:
#             score = m.player2_score
#             opp_score = m.player1_score
#             bonus = 1 if m.player2_new_opponent else 0
#         if score > opp_score:
#             wins += 1
#             points = 3
#         elif score < opp_score:
#             losses += 1
#             points = 1
#         else:
#             draws += 1
#             points = 2
#         total_points += points + bonus
#     win_rate = (wins / total_matches * 100) if total_matches > 0 else 0
#     stats = {
#         'total_matches': total_matches,
#         'wins': wins,
#         'draws': draws,
#         'losses': losses,
#         'total_points': total_points,
#         'win_rate': win_rate
#     }
#     return render_template('user_history.html', user=user, stats=stats, league_matches=league_matches)

@app.route('/user/<int:user_id>')
def user_history(user_id):
    user = User.query.get_or_404(user_id)
    # Retrieve all matches for the user, regardless of event.
    matches = Match.query.filter(
        ((Match.player1_id == user.id) | (Match.player2_id == user.id))
    ).order_by(Match.submission_date.desc()).all()
    # Group matches by event: use key "League" if event_id is None, otherwise use the event name.
    grouped_matches = {}
    for m in matches:
        key = "League" if m.event_id is None else m.event.name
        if key not in grouped_matches:
            grouped_matches[key] = []
        grouped_matches[key].append(m)
    return render_template('user_history.html', user=user, grouped_matches=grouped_matches)


@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    matches = Match.query.order_by(Match.submission_date.desc()).all()
    # Use pagination for events (no hard cap of 3)
    page = request.args.get('page', 1, type=int)
    events_pagination = Event.query.order_by(Event.event_date.desc()).paginate(page=page, per_page=5, error_out=False)
    events = events_pagination.items
    return render_template('admin_dashboard.html', users=users, matches=matches, events=events, pagination=events_pagination)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    new_password = secrets.token_urlsafe(8)
    user.set_password(new_password)
    db.session.commit()
    app.logger.info(f"Password for user {user.username} reset. New password: {new_password}")
    flash(f"Password for user {user.username} has been reset. New password: {new_password}", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        new_username = request.form.get('username')
        is_admin_val = request.form.get('is_admin')
        user.username = new_username
        user.is_admin = True if is_admin_val == 'on' else False
        db.session.commit()
        flash('User details updated.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/edit_match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def edit_match(match_id):
    if not current_user.is_admin:
        abort(403)
    match = Match.query.get_or_404(match_id)
    users = User.query.all()
    if request.method == 'POST':
        match_date_str = request.form.get('match_date')
        try:
            match.match_date = datetime.fromisoformat(match_date_str)
        except ValueError:
            flash('Invalid match date format.', 'danger')
            return redirect(url_for('edit_match', match_id=match_id))
        match.player1_id = int(request.form.get('player1'))
        match.player2_id = int(request.form.get('player2'))
        match.player1_army = request.form.get('player1_army')
        match.player2_army = request.form.get('player2_army')
        match.player1_detachment = request.form.get('player1_detachment')
        match.player2_detachment = request.form.get('player2_detachment')
        try:
            match.player1_score = int(request.form.get('player1_score'))
            match.player2_score = int(request.form.get('player2_score'))
        except ValueError:
            flash('Scores must be integers.', 'danger')
            return redirect(url_for('edit_match', match_id=match_id))
        db.session.commit()
        flash('Match updated.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_match.html', match=match, users=users)

# --------------------
# Tournament Event Management Routes
# --------------------
@app.route('/admin/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        name = request.form.get('name')
        event_date_str = request.form.get('event_date')
        try:
            event_date = datetime.fromisoformat(event_date_str) if event_date_str else datetime.utcnow()
        except ValueError:
            flash('Invalid event date format.', 'danger')
            return redirect(url_for('create_event'))
        event_type = request.form.get('event_type')  # 'league' or 'tournament'
        description = request.form.get('description')
        num_rounds = int(request.form.get('num_rounds')) if request.form.get('num_rounds') else 3
        new_event = Event(name=name, event_date=event_date, event_type=event_type, description=description,
                          num_rounds=num_rounds, current_round=1)
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_create_event.html')
@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('admin_create_user'))
        new_password = secrets.token_urlsafe(8)
        new_user = User(username=username)
        new_user.set_password(new_password)
        is_admin_val = request.form.get('is_admin')
        new_user.is_admin = True if is_admin_val == 'on' else False
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"Created user {username} with password: {new_password}")
        flash(f"User created. Username: {username}. New password: {new_password}", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_create_user.html')

@app.route('/admin/add_event_participants/<int:event_id>', methods=['GET', 'POST'])
@login_required
def add_event_participants(event_id):
    if not current_user.is_admin:
        abort(403)
    event = Event.query.get_or_404(event_id)
    all_users = User.query.all()
    if request.method == 'POST':
        selected_user_ids = request.form.getlist('participants')
        event.participants = []  # Clear current participants
        for uid in selected_user_ids:
            user = User.query.get(int(uid))
            if user:
                event.participants.append(user)
        db.session.commit()
        flash('Event participants updated.', 'success')
        return redirect(url_for('event_detail', event_id=event.id))
    return render_template('admin_add_event_participants.html', event=event, all_users=all_users)

@app.route('/admin/tournament_round/<int:event_id>', methods=['GET'], endpoint='admin_tournament_round')
@login_required
def admin_tournament_round(event_id):
    if not current_user.is_admin:
        abort(403)
    event = Event.query.get_or_404(event_id)
    # If no matches exist for round 1 and current_round is 1, generate initial pairings automatically
    if event.current_round == 1:
        existing = Match.query.filter_by(event_id=event.id, round_number=1).first()
        if not existing:
            # Generate initial pairings (random)
            participants = list(event.participants)
            random.shuffle(participants)
            new_matches = []
            i = 0
            while i < len(participants) - 1:
                p1 = participants[i]
                p2 = participants[i+1]
                new_matches.append(Match(
                    match_date=datetime.utcnow(),
                    player1_id=p1.id,
                    player2_id=p2.id,
                    player1_army="",
                    player2_army="",
                    player1_detachment="",
                    player2_detachment="",
                    player1_score=0,
                    player2_score=0,
                    player1_new_opponent=False,
                    player2_new_opponent=False,
                    event_id=event.id,
                    round_number=1
                ))
                i += 2
            if len(participants) % 2 == 1:
                bye_player = participants[-1]
                new_matches.append(Match(
                    match_date=datetime.utcnow(),
                    player1_id=bye_player.id,
                    player2_id=bye_player.id,
                    player1_army="Bye",
                    player2_army="Bye",
                    player1_detachment="",
                    player2_detachment="",
                    player1_score=3,
                    player2_score=0,
                    player1_new_opponent=False,
                    player2_new_opponent=False,
                    event_id=event.id,
                    round_number=1
                ))
            db.session.add_all(new_matches)
            db.session.commit()
    matches = Match.query.filter_by(event_id=event.id, round_number=event.current_round).all()
    return render_template('admin_tournament_round.html', event=event, matches=matches)

@app.route('/admin/submit_round_scores/<int:event_id>', methods=['POST'])
@login_required
def submit_round_scores(event_id):
    if not current_user.is_admin:
        abort(403)
    event = Event.query.get_or_404(event_id)
    current_round = event.current_round
    matches = Match.query.filter_by(event_id=event.id, round_number=current_round).all()
    for match in matches:
        p1_score = request.form.get(f"score_{match.id}_p1")
        p2_score = request.form.get(f"score_{match.id}_p2")
        try:
            p1_score = int(p1_score)
            p2_score = int(p2_score)
        except (ValueError, TypeError):
            flash("All scores must be integers.", "danger")
            return redirect(url_for('admin_tournament_round', event_id=event.id))
        match.player1_score = p1_score
        match.player2_score = p2_score
    db.session.commit()
    flash(f"Scores for round {current_round} submitted.", "success")
    if current_round < event.num_rounds:
        return redirect(url_for('generate_tournament_round', event_id=event.id))
    else:
        scores = {}
        for participant in event.participants:
            scores[participant.id] = get_tournament_score(participant, event)
        champion_id = max(scores, key=scores.get)
        event.champion_id = champion_id
        event.is_finished = True
        db.session.commit()
        flash("Tournament finalized. Champion determined.", "success")
        return redirect(url_for('event_detail', event_id=event.id))

# --------------------
# Tournament Round Generation (Updated)
# --------------------
@app.route('/admin/generate_tournament_round/<int:event_id>', methods=['GET', 'POST'])
@login_required
def generate_tournament_round(event_id):
    if not current_user.is_admin:
        abort(403)
    event = Event.query.get_or_404(event_id)
    if event.event_type != 'tournament':
        flash('This event is not a tournament.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))
    # Increment round (for rounds 2+; for round 1 initial pairings should be auto‑generated in admin_tournament_round)
    event.current_round += 1
    current_round = event.current_round
    # Sort participants by tournament score (ignoring unplayed matches)
    participants = list(event.participants)
    participants.sort(key=lambda u: get_tournament_score(u, event), reverse=True)
    new_matches = []
    i = 0
    while i < len(participants) - 1:
        p1 = participants[i]
        p2 = participants[i+1]
        new_matches.append(Match(
            match_date=datetime.utcnow(),
            player1_id=p1.id,
            player2_id=p2.id,
            player1_army="",
            player2_army="",
            player1_detachment="",
            player2_detachment="",
            player1_score=0,
            player2_score=0,
            player1_new_opponent=False,
            player2_new_opponent=False,
            event_id=event.id,
            round_number=current_round
        ))
        i += 2
    if len(participants) % 2 == 1:
        bye_player = participants[-1]
        new_matches.append(Match(
            match_date=datetime.utcnow(),
            player1_id=bye_player.id,
            player2_id=bye_player.id,
            player1_army="Bye",
            player2_army="Bye",
            player1_detachment="",
            player2_detachment="",
            player1_score=0,  # Bye match should not add score automatically; you may later award a win manually if desired.
            player2_score=0,
            player1_new_opponent=False,
            player2_new_opponent=False,
            event_id=event.id,
            round_number=current_round
        ))
    for m in new_matches:
        db.session.add(m)
    db.session.commit()
    flash(f"Tournament round {current_round} pairings generated.", "success")
    return redirect(url_for('admin_tournament_round', event_id=event.id))

@app.route('/admin/finalize_event/<int:event_id>', methods=['POST'])
@login_required
def finalize_event(event_id):
    if not current_user.is_admin:
        abort(403)
    event = Event.query.get_or_404(event_id)
    event.is_finished = True
    db.session.commit()
    flash("Event finalized.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    matches = Match.query.filter_by(event_id=event.id).order_by(Match.match_date.desc()).all()
    if event.event_type == 'league':
        ranking = []
        stats = {}
        for match in matches:
            for pid in [match.player1_id, match.player2_id]:
                if pid not in stats:
                    stats[pid] = {'points': 0, 'wins': 0, 'draws': 0, 'losses': 0}
            if match.player1_score > match.player2_score:
                stats[match.player1_id]['points'] += 3
                stats[match.player2_id]['points'] += 1
                stats[match.player1_id]['wins'] += 1
                stats[match.player2_id]['losses'] += 1
            elif match.player1_score < match.player2_score:
                stats[match.player2_id]['points'] += 3
                stats[match.player1_id]['points'] += 1
                stats[match.player2_id]['wins'] += 1
                stats[match.player1_id]['losses'] += 1
            else:
                stats[match.player1_id]['points'] += 2
                stats[match.player2_id]['points'] += 2
                stats[match.player1_id]['draws'] += 1
                stats[match.player2_id]['draws'] += 1
        ranking = []
        for uid, stat in stats.items():
            user = User.query.get(uid)
            ranking.append({
                'username': user.username,
                'profile_picture': user.profile_picture,
                'points': stat['points'],
                'wins': stat['wins'],
                'draws': stat['draws'],
                'losses': stat['losses']
            })
        ranking.sort(key=lambda x: x['points'], reverse=True)
    else:
        # Tournament: use our new helper and include win/loss stats.
        ranking = []
        for participant in event.participants:
            pts, wins, draws, losses = get_tournament_stats(participant, event)
            ranking.append({
                'username': participant.username,
                'profile_picture': participant.profile_picture,
                'points': pts,
                'wins': wins,
                'draws': draws,
                'losses': losses
            })
        ranking.sort(key=lambda x: x['points'], reverse=True)
    return render_template('event_detail.html', event=event, matches=matches, ranking=ranking)

if __name__ == '__main__':
    app.run()
