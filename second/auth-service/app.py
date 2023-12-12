from flask import Flask, request, jsonify, make_response, render_template, redirect, url_for
from datetime import timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__, template_folder='views')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Configure database URI
app.config['SECRET_KEY'] = '1b11726c'
app.config['JWT_SECRET_KEY'] = '1b11726c-6a57-4562-bd74-1164b6439469'  # Change this secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Talisman with a strict content security policy
Talisman(app, content_security_policy={'default-src': ['\'self\'',],})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            access_token = create_access_token(identity=user.username)
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('access_token_cookie', access_token, httponly=True, samesite='Lax')
            return response
        else:
            return render_template('login.html', form=form, error="Invalid credentials")

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'User already exists', 409

        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return render_template('dashboard.html', user=current_user)

if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()
        db.create_all()
    app.run(debug=True)