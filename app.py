import ast
from flask import Flask, render_template, request,redirect, url_for,flash , session, jsonify
from dbConnector import UseDatabase
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from flask_bcrypt import Bcrypt
from flask_session import Session
import secrets
from datetime import timedelta 


dbconfig = {'host': '127.0.0.1', 'user': 'root', 'password': '97082', 'database': 'oops5'}

app = Flask(__name__)


#auth config
app.config['SECRET_KEY'] = '7!1:2^64e3u/ghdr?83lawe;#;;./' #it will kill session if server goes down, may is hould give a hard coded random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:97082@localhost/oops5'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#session config
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENET'] = True
app.permanent_session_lifetime = timedelta(days=2) #expire after 30 days
Session(app)

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# table creation for auth
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



@app.route('/logout' , methods=['GET','POST'])
#@login_required
def logout():
    if request.method == 'POST' :
        response = request.form['response']
        if response == 'yes' :
            logout_user()
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('homepage'))
    
    return render_template('logout.html', activelogout='active', css='/static/logoutcss.css',distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})


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
            flash('already an user with that email , enter different email or login', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(fname=fname, lname=lname , email=email)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()
            flash('Sign UP successful. Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html',activesignup='active', css='/static/signup.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            #app.config['SESSION_PERMANENET'] = True   #should i do it here ?
            session['email'] = email                   #session will be saved with respect to email
            return redirect(url_for('homepage'))
        else:
            flash('Login failed. Check your credentials', 'danger')
    return render_template('login.html', activelogin='active',css='static/login.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/') #Done
def homepage() -> 'Html page':
    return render_template('homepage.html', activehome='active',css='static/homepagecss.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})   

@app.route('/product')  #Done
def product() -> 'Html Page':
    with UseDatabase(dbconfig) as cursor:
        cmd = "SELECT sympname FROM symptoms"
        cursor.execute(cmd)
        symptomslt = cursor.fetchall()

    symptoms = [item for sublist in symptomslt for item in sublist]
    
    return render_template('product.html', activeproduct='active',css='static/productcss.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']}, symptoms=symptoms)  

@app.route('/about_us') #Sourish Will Do It
def about_us() -> 'Html Page':

    return render_template('about_us.html', activeabout='active',css='static/about_uscss.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/result1', methods=['GET', 'POST']) #Anybody Can Try This Best One Will Be Done
def tool1() -> 'Name of Possible Diseases':

    symptom1 = request.form['symptom1']
    symptom2 = request.form['symptom2']
    symptom3 = request.form['symptom3']
    symptom4 = request.form['symptom4']
    symptom5 = request.form['symptom5']

    with UseDatabase(dbconfig) as cursor:
        cmd = "SELECT sympkey FROM symptoms WHERE sympname IN (%s,%s,%s,%s,%s)"
        cursor.execute(cmd,(symptom1, symptom2, symptom3, symptom4, symptom5))
        sympkeys = cursor.fetchall()
        sympkey_tuple = tuple([i[0] for i in sympkeys])

        cmd = "SELECT diskey, sympkey FROM symptodis WHERE sympkey IN {}".format(sympkey_tuple)
        cursor.execute(cmd)
        distosymp = cursor.fetchall()
        
        distosymp_dict = {}
        for i in distosymp:
            cmd = "SELECT disname FROM disease WHERE diskey=%s"
            cursor.execute(cmd,(i[0],))
            disname = cursor.fetchone()
            if disname[0] not in distosymp_dict:
                distosymp_dict[disname[0]] = [[i[1]]]
            else:
                distosymp_dict[disname[0]][0].append(i[1])

        key_length_pairs = [(key, len(value[0])) for key, value in distosymp_dict.items()]
        key_length_pairs.sort(key=lambda x: x[1], reverse=True)

        colors = ['#36a2eb', '#ff6384', '#ff9f40', '#ffcd56', '#22cfcf']
        classnames = ['disbar1', 'disbar2', 'disbar3', 'disbar4', 'disbar5']
        i = 0
        distosymp_ordered = {}
        for key,value in key_length_pairs:
            distosymp_ordered[key] = distosymp_dict[key]
            percentage = len(distosymp_dict[key][0])/5 * 100
            distosymp_ordered[key].append(percentage)
            distosymp_ordered[key].append(colors[i])
            distosymp_ordered[key].append(classnames[i])
            i = i+1

        disnameforJS = []
        percentageforJS = []
        for key, value in  distosymp_ordered.items():
            disnameforJS.append(key)
            percentageforJS.append(value[1])

    return render_template('result1.html', activeproduct='active', css='static/result1css.css', distosymp_ordered=distosymp_ordered, disnameforJS=disnameforJS, percentageforJS=percentageforJS)

@app.route('/question/<sympkeys>/<disname>')
def question(sympkeys, disname) -> 'Questions Of a Particular Disease':

    sympkeys = ast.literal_eval(sympkeys)
    with UseDatabase(dbconfig) as cursor:
        cmd = "SELECT diskey FROM disease WHERE disname = %s"
        cursor.execute(cmd, (disname, ))
        diskey_tuple = cursor.fetchone()

        cmd = "SELECT sympkey FROM symptodis WHERE diskey = %s"
        cursor.execute(cmd, (diskey_tuple[0], ))
        sympkeys_listuple = cursor.fetchall()

        question_sympkeys = []
        for i in sympkeys_listuple:
            if i[0] not in sympkeys:
                question_sympkeys.append(i[0])

        if len(question_sympkeys)==0:
            return redirect(url_for('result2', disease=disname, j='0'))

        question_sympkeys = tuple(question_sympkeys)     
        cmd = "SELECT question, checks FROM symptodis WHERE sympkey IN {}".format(question_sympkeys)
        cursor.execute(cmd)
        questions = cursor.fetchall()

        questionlist = []
        j=0
        for i in questions:
            j=j+1
            a = list(i)
            a.append(j)
            questionlist.append(a)
        
    return render_template('question.html', activeproduct='active', css='/static/questioncss.css', questions=questionlist, disease=disname, j=j, distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/result2/<disease>/<j>', methods=['GET', 'POST'])
def result2(disease, j) -> 'Chances Of a Particular Disease':

    j = int(j)
    with UseDatabase(dbconfig) as cursor:
        cmd = "SELECT diskey, link FROM disease WHERE disname=%s"
        cursor.execute(cmd, (disease, ))
        disandlink = cursor.fetchone()

        cmd = "SELECT sympkey FROM symptodis WHERE diskey=%s"
        cursor.execute(cmd, (disandlink[0], ))
        sympkeys = cursor.fetchall()
        sympkeyslen = len(sympkeys)

        count = sympkeyslen - j 

        responeslist = []
        for i in range(1,j+1):
            responeslist.append(request.form['response{}'.format(i)])

        for i in responeslist:
            if i=='yes':
                count = count +1

        percantage = count/sympkeyslen*100
        percantage = int(percantage) 

    return render_template('result2.html', activeproduct='active', css='/static/result2css.css', disease=disease, percantage=percantage, link=disandlink[1], distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})



app.run(debug=True)