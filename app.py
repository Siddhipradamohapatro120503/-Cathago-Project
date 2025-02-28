from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.decomposition import NMF
import numpy as np
from collections import Counter, defaultdict
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo
from io import StringIO, BytesIO
import csv
from sqlalchemy import func

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Keep users logged in for 7 days

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    credits = db.Column(db.Integer, default=10)
    last_credit_reset = db.Column(db.DateTime, default=datetime.utcnow)
    documents = db.relationship('Document', backref='owner', lazy=True)
    credit_requests = db.relationship('CreditRequest', backref='user', lazy=True)
    sessions = db.relationship('UserSession', back_populates='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topics = db.Column(db.String(255), nullable=True)  # Store top topics as JSON string

class CreditRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, denied
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    processed_date = db.Column(db.DateTime, nullable=True)

class UserSession(db.Model):
    """Model for tracking user sessions."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', back_populates='sessions')

# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def reset_daily_credits():
    """Reset credits for users who haven't had a reset in 24 hours"""
    users = User.query.all()
    now = datetime.utcnow()
    for user in users:
        # Check if last reset was before today's midnight
        today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if user.last_credit_reset < today_midnight:
            user.credits = 20  # Reset to daily limit
            user.last_credit_reset = now
    db.session.commit()

@app.before_request
def update_user_session():
    """Update user's last activity time."""
    if current_user.is_authenticated:
        # Get or create user session
        session_id = session.get('session_id')
        if session_id:
            user_session = UserSession.query.get(session_id)
        else:
            user_session = UserSession(
                user_id=current_user.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(user_session)
            db.session.flush()  # Get the ID before committing
            session['session_id'] = user_session.id
        
        # Update last activity
        if user_session:
            user_session.last_activity = datetime.utcnow()
            db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose a different one.')
            return render_template('register.html', form=form)
        
        try:
            # Create new user
            user = User(
                username=form.username.data,
                email=form.username.data + '@example.com',
                is_admin=False,
                credits=20  # Starting credits
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            
            # Log success and redirect
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            print(f"Registration error: {str(e)}")
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
        flash('Invalid username or password')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    # Mark current session as inactive
    session_id = session.get('session_id')
    if session_id:
        user_session = UserSession.query.get(session_id)
        if user_session:
            user_session.is_active = False
            db.session.commit()
    
    # Clear session
    session.clear()
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        return render_template('dashboard.html', 
                             now=datetime.utcnow(),
                             timedelta=timedelta)  # Pass timedelta to the template
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        return str(e), 500

@app.route('/document/<int:doc_id>', methods=['GET', 'DELETE'])
@login_required
def document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'DELETE':
        db.session.delete(doc)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({
        'id': doc.id,
        'filename': doc.filename,
        'content': doc.content,
        'upload_date': doc.upload_date.strftime('%Y-%m-%d %H:%M'),
        'topics': json.loads(doc.topics) if doc.topics else []
    })

@app.route('/similar/<int:doc_id>')
@login_required
def similar_documents(doc_id):
    """Get similar documents for a given document ID."""
    document = Document.query.get_or_404(doc_id)
    
    # Check if user owns the document or is admin
    if document.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Not authorized'}), 403
    
    similar_docs = find_similar_documents(document)
    
    return jsonify({
        'similar_documents': [
            {
                'id': doc.id,
                'filename': doc.filename,
                'content_preview': doc.content[:200] + '...' if len(doc.content) > 200 else doc.content,
                'similarity': round(score * 100, 1)  # Convert to percentage
            }
            for doc, score in similar_docs
        ]
    })

@app.route('/scan', methods=['POST'])
@login_required
def scan_document():
    if current_user.credits <= 0:
        return jsonify({'error': 'No credits available'}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        content = file.read().decode('utf-8')
        
        # Extract topics from the document
        topics = extract_topics(content)
        
        # Create new document
        document = Document(
            filename=file.filename,
            content=content,
            user_id=current_user.id,
            topics=json.dumps(topics)
        )
        current_user.credits -= 1
        db.session.add(document)
        db.session.commit()
        
        # Find similar documents using TF-IDF and cosine similarity
        similar_docs = find_similar_documents(document)
        
        # Format matches for response
        matches = [
            {
                'id': doc.id,
                'filename': doc.filename,
                'similarity': round(score * 100, 1),  # Convert to percentage
                'preview': doc.content[:200] + '...' if len(doc.content) > 200 else doc.content
            }
            for doc, score in similar_docs
        ]
        
        return jsonify({
            'message': 'Document uploaded successfully',
            'matches': matches,
            'remaining_credits': current_user.credits
        })

def find_similar_documents(new_document):
    """Find similar documents using TF-IDF and cosine similarity."""
    documents = Document.query.filter(Document.id != new_document.id).all()
    
    if not documents:
        return []
    
    # Create corpus including the new document
    corpus = [doc.content for doc in documents]
    corpus.append(new_document.content)
    
    # Calculate TF-IDF
    vectorizer = TfidfVectorizer(
        stop_words='english',
        max_features=5000,
        ngram_range=(1, 2)  # Include both unigrams and bigrams
    )
    tfidf_matrix = vectorizer.fit_transform(corpus)
    
    # Calculate cosine similarity between the new document and all others
    doc_similarities = cosine_similarity(
        tfidf_matrix[-1:],  # New document's vector
        tfidf_matrix[:-1]   # All other documents' vectors
    )[0]
    
    # Create list of (document, similarity_score) tuples
    similar_docs = list(zip(documents, doc_similarities))
    
    # Sort by similarity score in descending order
    similar_docs.sort(key=lambda x: x[1], reverse=True)
    
    # Return top 5 similar documents with similarity scores
    return [(doc, float(score)) for doc, score in similar_docs[:5] if score > 0.1]

def extract_topics(text, num_topics=3, num_words=5):
    """Extract main topics from text using NMF"""
    vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
    tfidf = vectorizer.fit_transform([text])
    
    nmf = NMF(n_components=num_topics)
    nmf.fit(tfidf)
    
    feature_names = vectorizer.get_feature_names_out()
    topics = []
    for topic_idx, topic in enumerate(nmf.components_):
        top_words = [feature_names[i] for i in topic.argsort()[:-num_words-1:-1]]
        topics.append(top_words)
    
    return topics

@app.route('/request_credits', methods=['POST'])
@login_required
def request_credits():
    """Request additional credits"""
    requested_amount = request.json.get('amount', 20)
    
    # Check if user already has pending requests
    pending_request = CreditRequest.query.filter_by(
        user_id=current_user.id, 
        status='pending'
    ).first()
    
    if pending_request:
        return jsonify({
            'error': 'You already have a pending credit request'
        }), 400
    
    credit_request = CreditRequest(
        user_id=current_user.id,
        amount=requested_amount
    )
    db.session.add(credit_request)
    db.session.commit()
    
    return jsonify({
        'message': 'Credit request submitted successfully',
        'request_id': credit_request.id
    })

@app.route('/admin/credit-requests')
@login_required
def admin_credit_requests():
    """Admin page to view and manage credit requests."""
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # Get all credit requests ordered by date (newest first)
    credit_requests = CreditRequest.query.order_by(
        CreditRequest.request_date.desc()
    ).all()
    
    return render_template(
        'admin/credit_requests.html',
        credit_requests=credit_requests
    )

@app.route('/admin/credits/<int:request_id>/<action>', methods=['POST'])
@login_required
def handle_credit_request(request_id, action):
    """Handle credit request approval/denial."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    credit_request = CreditRequest.query.get_or_404(request_id)
    
    if credit_request.status != 'pending':
        return jsonify({'error': 'Request has already been processed'}), 400
    
    if action not in ['approve', 'deny']:
        return jsonify({'error': 'Invalid action'}), 400
    
    try:
        if action == 'approve':
            # Add credits to user's account
            credit_request.user.credits += credit_request.amount
            credit_request.status = 'approved'
            message = 'Credit request approved successfully'
        else:
            credit_request.status = 'denied'
            message = 'Credit request denied'
        
        credit_request.processed_date = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': message,
            'new_credits': credit_request.user.credits if action == 'approve' else None
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error processing request'}), 500

@app.route('/admin/adjust-credits/<int:user_id>', methods=['POST'])
@login_required
def adjust_user_credits(user_id):
    """Manually adjust a user's credit balance (admin only)."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    user = User.query.get_or_404(user_id)
    adjustment = request.json.get('adjustment')
    
    if adjustment is None:
        return jsonify({'error': 'Credit adjustment amount is required'}), 400
    
    try:
        # Prevent negative credit balance
        new_balance = max(0, user.credits + adjustment)
        user.credits = new_balance
        db.session.commit()
        
        return jsonify({
            'message': 'Credit balance adjusted successfully',
            'new_credits': user.credits
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error adjusting credits'}), 500

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    """Admin analytics dashboard showing system usage statistics."""
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # Get current date for daily stats
    today = datetime.utcnow().date()
    
    # Calculate total users and documents
    total_users = User.query.count()
    total_documents = Document.query.count()
    
    # Calculate daily scans (documents uploaded per day)
    daily_scans = defaultdict(int)
    recent_docs = Document.query.filter(
        Document.upload_date >= today - timedelta(days=30)
    ).all()
    
    for doc in recent_docs:
        scan_date = doc.upload_date.date()
        daily_scans[scan_date.isoformat()] += 1
    
    # Calculate credit statistics
    credits = [user.credits for user in User.query.all()]
    credit_stats = {
        'average': sum(credits) / len(credits) if credits else 0,
        'min': min(credits) if credits else 0,
        'max': max(credits) if credits else 0
    }
    
    # Get topic distribution
    topic_distribution = defaultdict(int)
    for doc in Document.query.all():
        if doc.topics:
            topics = json.loads(doc.topics)
            for topic_words in topics:
                topic_distribution[' '.join(topic_words[:3])] += 1
    
    # Sort topics by frequency
    topic_distribution = dict(sorted(
        topic_distribution.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10])  # Keep top 10 topics
    
    analytics = {
        'total_users': total_users,
        'total_documents': total_documents,
        'daily_scans': dict(daily_scans),
        'credit_stats': credit_stats,
        'topic_distribution': topic_distribution,
        'today': today.isoformat()
    }
    
    return render_template('admin/analytics.html', analytics=analytics)

@app.route('/admin/active-users')
@login_required
def active_users():
    """View active users in the last 15 minutes."""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get sessions active in the last 15 minutes
    cutoff_time = datetime.utcnow() - timedelta(minutes=15)
    active_sessions = UserSession.query\
        .filter(UserSession.last_activity >= cutoff_time)\
        .filter(UserSession.is_active == True)\
        .order_by(UserSession.last_activity.desc())\
        .all()
    
    return render_template(
        'admin/active_users.html',
        active_sessions=active_sessions
    )

@app.route('/profile')
@login_required
def profile():
    """User profile page showing stats and activity."""
    # Get user's documents
    user_docs = Document.query.filter_by(owner=current_user).order_by(
        Document.upload_date.desc()
    ).limit(5).all()
    
    # Get user's credit requests
    credit_requests = CreditRequest.query.filter_by(user=current_user).order_by(
        CreditRequest.request_date.desc()
    ).limit(5).all()
    
    # Build recent activity feed
    recent_activity = []
    
    # Add document scans to activity
    for doc in user_docs:
        recent_activity.append({
            'type': 'scan',
            'action': 'Scanned document',
            'filename': doc.filename,
            'timestamp': doc.upload_date
        })
    
    # Add credit requests to activity
    for req in credit_requests:
        status_badge = {
            'pending': 'badge-blue',
            'approved': 'badge-green',
            'denied': 'badge-red'
        }.get(req.status, 'badge-gray')
        
        recent_activity.append({
            'type': 'credit_request',
            'action': f'Requested {req.amount} credits',
            'status': req.status,
            'status_badge': status_badge,
            'timestamp': req.request_date
        })
    
    # Sort activity by timestamp
    recent_activity.sort(key=lambda x: x['timestamp'], reverse=True)
    
    stats = {
        'total_scans': Document.query.filter_by(owner=current_user).count(),
        'recent_documents': user_docs,
        'credit_requests': credit_requests,
        'recent_activity': recent_activity[:10]  # Show last 10 activities
    }
    
    return render_template('profile.html', stats=stats)

@app.route('/export/scan-history', methods=['GET'])
@login_required
def export_scan_history():
    """Export user's scan history as a CSV file."""
    try:
        # Get user's documents with related information
        documents = Document.query.filter_by(user_id=current_user.id)\
            .order_by(Document.upload_date.desc())\
            .all()
        
        # Create CSV in memory
        si = StringIO()
        writer = csv.writer(si)
        
        # Write header
        writer.writerow([
            'Document Name',
            'Upload Date',
            'Topics',
            'Similar Documents'
        ])
        
        # Write document data
        for doc in documents:
            # Convert topics from JSON string to list and back to string
            try:
                topics = json.loads(doc.topics) if doc.topics else []
                topics_str = ', '.join(str(topic) for topic in topics) if topics else 'No topics extracted'
            except (json.JSONDecodeError, TypeError):
                topics_str = 'No topics extracted'
            
            # Get all other documents by this user
            other_docs = Document.query.filter(
                Document.id != doc.id,
                Document.user_id == current_user.id
            ).all()
            
            # Calculate similarities using TF-IDF
            if other_docs:
                # Create TF-IDF vectorizer
                vectorizer = TfidfVectorizer(stop_words='english')
                
                # Get document contents
                all_contents = [doc.content] + [d.content for d in other_docs]
                
                # Calculate TF-IDF matrix
                try:
                    tfidf_matrix = vectorizer.fit_transform(all_contents)
                    
                    # Calculate cosine similarities
                    similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]
                    
                    # Get indices of top 3 similar documents
                    similar_indices = similarities.argsort()[-3:][::-1]
                    
                    # Get similar document names and similarities
                    similar_docs = [
                        f"{other_docs[idx].filename} ({similarities[idx]:.2f})"
                        for idx in similar_indices
                        if similarities[idx] > 0.1  # Only include if similarity > 0.1
                    ]
                    similar_docs_str = ', '.join(similar_docs) if similar_docs else 'None'
                except Exception:
                    similar_docs_str = 'Error calculating similarities'
            else:
                similar_docs_str = 'No other documents'
            
            writer.writerow([
                doc.filename,
                doc.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
                topics_str,
                similar_docs_str
            ])
        
        # Convert to BytesIO
        output = BytesIO()
        output.write(si.getvalue().encode('utf-8'))
        output.seek(0)
        
        # Prepare the output
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'scan_history_{timestamp}.csv'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.template_filter('from_json')
def from_json(value):
    """Convert JSON string to Python object for use in templates."""
    return json.loads(value) if value else []

def init_db():
    """Initialize the database only if it doesn't exist."""
    with app.app_context():
        # Create all tables if they don't exist
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Create admin user
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                credits=100
            )
            admin.set_password('admin')
            db.session.add(admin)
            
            # Create test user
            user = User(
                username='test',
                email='test@example.com',
                is_admin=False,
                credits=20
            )
            user.set_password('test')
            db.session.add(user)
            
            # Add some test credit requests
            test_request = CreditRequest(
                user=user,
                amount=50,
                status='pending',
                request_date=datetime.utcnow()
            )
            db.session.add(test_request)
            
            db.session.commit()

if __name__ == '__main__':
    init_db()  # Initialize database only if needed
    app.run(debug=True)
