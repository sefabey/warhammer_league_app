from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from passlib.hash import pbkdf2_sha256
import secrets, os
from datetime import datetime
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///league.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'profile_pics')
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# League Rules:
# 1. Each player can play two league games per week, not facing the same opponent in the same week, only at Dark Fire Cafe.
# 2. Each list must be 2000 points, following standard matched play rules.
# 3. Missions come from the Pariah Nexus Deck, or if both players agree, use UKTC/WTC.
# 4. Bonus: 1 extra point is awarded for playing a new opponent (if the matchup is a first-time meeting).
# 5. Additionally, 1 extra point is awarded for registering (granted once, after the first game).
# 6. Scores must be recorded on the league tracker before leaving the premises.

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

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    player1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    player2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    player1_army = db.Column(db.String(80))
    player2_army = db.Column(db.String(80))
    player1_score = db.Column(db.Integer, nullable=False)
    player2_score = db.Column(db.Integer, nullable=False)
    player1_new_opponent = db.Column(db.Boolean, default=False)
    player2_new_opponent = db.Column(db.Boolean, default=False)

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

@app.route('/')
def index():
    matches = Match.query.order_by(Match.submission_date.desc()).limit(10).all()
    users = User.query.all()
    stats = {}
    for user in users:
        stats[user.id] = {
            'id': user.id,
            'username': user.username,
            'points': 0,
            'matches': 0,
            'profile_picture': user.profile_picture,
            'wins': 0,
            'draws': 0,
            'losses': 0
        }
    for match in Match.query.all():
        # Determine points
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

        # Compute win/draw/loss record
        if match.player1_score > match.player2_score:
            stats[match.player1_id]['wins'] += 1
            stats[match.player2_id]['losses'] += 1
        elif match.player1_score < match.player2_score:
            stats[match.player1_id]['losses'] += 1
            stats[match.player2_id]['wins'] += 1
        else:
            stats[match.player1_id]['draws'] += 1
            stats[match.player2_id]['draws'] += 1

    league_table = list(stats.values())
    league_table.sort(key=lambda x: x['points'], reverse=True)
    return render_template('index.html', matches=matches, league_table=league_table)

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
        # If no users exist yet, automatically make this user an admin.
        if User.query.first() is None:
            new_user.is_admin = True
        db.session.add(new_user)
        db.session.commit()
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
        try:
            player1_score = int(request.form.get('player1_score'))
            player2_score = int(request.form.get('player2_score'))
        except ValueError:
            flash('Scores must be integers.', 'danger')
            return redirect(url_for('new_match'))

        # Automatically deduce new opponent bonus (if these two players haven't met before)
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
            player1_score=player1_score,
            player2_score=player2_score,
            player1_new_opponent=new_bonus1,
            player2_new_opponent=new_bonus2
        )
        db.session.add(match)
        db.session.commit()

        # Award registration bonus on first match if not already given.
        for uid in [player1_id, player2_id]:
            user = User.query.get(uid)
            if not user.registration_bonus:
                user.registration_bonus = True
        db.session.commit()

        flash('Match recorded successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('new_match.html', users=users)

@app.route('/user/<int:user_id>')
def user_history(user_id):
    user = User.query.get_or_404(user_id)
    matches_as_player1 = Match.query.filter_by(player1_id=user.id).all()
    matches_as_player2 = Match.query.filter_by(player2_id=user.id).all()
    matches = matches_as_player1 + matches_as_player2
    matches.sort(key=lambda m: m.submission_date, reverse=True)

    total_matches = len(matches)
    wins = draws = losses = total_points = 0
    for m in matches:
        if m.player1_id == user.id:
            score = m.player1_score
            opp_score = m.player2_score
            bonus = 1 if m.player1_new_opponent else 0
        else:
            score = m.player2_score
            opp_score = m.player1_score
            bonus = 1 if m.player2_new_opponent else 0
        if score > opp_score:
            wins += 1
            points = 3
        elif score < opp_score:
            losses += 1
            points = 1
        else:
            draws += 1
            points = 2
        total_points += points + bonus

    stats = {
        'total_matches': total_matches,
        'wins': wins,
        'draws': draws,
        'losses': losses,
        'total_points': total_points
    }
    return render_template('user_history.html', user=user, matches=matches, stats=stats)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    matches = Match.query.order_by(Match.submission_date.desc()).all()
    return render_template('admin_dashboard.html', users=users, matches=matches)


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    new_password = secrets.token_urlsafe(8)
    user.set_password(new_password)
    db.session.commit()
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


if __name__ == '__main__':
    app.run(debug=True)
