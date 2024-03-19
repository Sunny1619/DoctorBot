from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_bcrypt import Bcrypt


# Configurations
app = Flask(__name__)

#auth config
app.config['SECRET_KEY'] = 'frgtrfgjrheniug45y98rugv/.hb'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:97082@localhost/oops5'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    __tablename__ = 'auth'
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = request.form['password']

        #only unique email
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return render_template('signup.html', e_message='there is already an account with this email , enter new email or login')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(fname=fname, lname=lname , email=email)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html',activesignup='active', css='/static/login.css')


@app.route('/login', methods=['GET', 'POST']) #Not Decided Yet
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials', 'danger')

    return render_template('login.html', activelogin='active',css='static/logincss.css')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True) 
