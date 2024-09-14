from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(200), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Ensure tables are created before first request
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    events = Event.query.all()
    if not events:
        return render_template('index.html', message="No events available. Please register as an admin.")
    return render_template('index.html', events=events)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        is_admin = True  # Register as an admin

        new_user = User(name=name, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('Admin registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    return render_template('login.html')

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access! Only admins can access this page.', 'danger')
        return redirect(url_for('index'))

    events = Event.query.all()
    return render_template('admin_dashboard.html', events=events)


@app.route('/event/new', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access! Only admins can create events.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        creator_id = session['user_id']
        event = Event(title=title, description=description, location=location, start_time=start_time, end_time=end_time, creator_id=creator_id)
        db.session.add(event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('event_create.html')

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    rsvps = RSVP.query.filter_by(event_id=event.id).all()
    return render_template('event_detail.html', event=event, rsvps=rsvps)

@app.route('/event/<int:event_id>/rsvp', methods=['POST'])
def rsvp(event_id):
    event = Event.query.get_or_404(event_id)
    user_name = request.form['name']
    user_email = request.form['email']
    status = request.form['status']
    rsvp = RSVP(user_name=user_name, user_email=user_email, event_id=event.id, status=status)
    db.session.add(rsvp)
    db.session.commit()
    flash(f'RSVP {status} submitted for {user_name}!', 'success')
    return redirect(url_for('event_detail', event_id=event.id))

@app.route('/event/<int:event_id>/delete', methods=['POST'])
def delete_event(event_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access! Only admins can delete events.', 'danger')
        return redirect(url_for('index'))
    
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/event/<int:event_id>/rsvps')
def view_rsvps(event_id):
    event = Event.query.get_or_404(event_id)
    rsvps = RSVP.query.filter_by(event_id=event_id).all()
    return render_template('admin_rsvps.html', event=event, rsvps=rsvps)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
