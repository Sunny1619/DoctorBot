import ast
from flask import Flask, render_template, request,redirect, url_for,flash , session, jsonify
from dbConnector import UseDatabase, UseDatabase1
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from flask_bcrypt import Bcrypt
from flask_session import Session
import secrets
from datetime import timedelta, date
import itertools, json
import mysql


dbconfig = {'host': '127.0.0.1', 'user': 'root', 'password': '97082', 'database': 'oops5'}
dbconfig2 = {'host': '127.0.0.1', 'user': 'root', 'password': '97082', 'database': 'auth5'}

app = Flask(__name__)


#auth config
app.config['SECRET_KEY'] = '7!1:2^64e3u/ghdr?83lawe;#;;./' #it will kill session if server goes down, may is hould give a hard coded random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:97082@localhost/auth5'
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
login_manager.login_view = 'login_Admin'

class UserAuth(UserMixin, db.Model):
    __tablename__ = 'userauth'
    user_id=db.Column(db.Integer , primary_key = True, autoincrement=False)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    organisation = db.Column(db.String(250) , nullable=False )
    admin_id = db.Column(db.Integer, db.ForeignKey('adminauth.admin_id'), nullable=False)
    role = db.Column(db.String(250), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return self.user_id

#root table
class AdminAuth(UserMixin, db.Model):
    __tablename__ = 'adminauth'
    admin_id=db.Column(db.Integer , primary_key = True, autoincrement=False)
    organisation = db.Column(db.String(250) , nullable=False )
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(250), nullable=False)
    orders = db.relationship('UserAuth', backref='adminauth', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return self.admin_id
    

# User Loader
@login_manager.user_loader
def load_user(id):
    user = UserAuth.query.get(int(id))
    if user:
        return user
    else:
        admin = AdminAuth.query.get(int(id))
        if admin:
            return admin
        else:
            return None



@app.route('/logout' , methods=['GET','POST'])
@login_required
def logout():
    if request.method == 'POST' :
        response = request.form['response']
        if response == 'yes' :
            logout_user()
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('homepage'))
    
    return render_template('logout.html', activelogout='active', css='/static/logoutcss.css',distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})


@app.route('/signup_User', methods=['GET', 'POST'])
def signup_User():
    if request.method == 'POST':
        name = request.form['fname']
        user_id = request.form['user_id']
        email = request.form['email']
        password = request.form['password1']

        existing_email = UserAuth.query.filter_by(email=email).first()
        if existing_email:
            return render_template('error.html',msg='Email already exits',link="/signup_User")
        else:
            with UseDatabase(dbconfig2) as cursor:
                cmd = "SELECT admin_id, name FROM govauth WHERE user_id=%s"
                cursor.execute(cmd,(user_id,))
                admin_data = cursor.fetchone()
                if admin_data==None:
                    return render_template('error.html',msg='No such user id under any admin',link='/signup_User')
                else:   
                    new_user = UserAuth(user_id=user_id,name=name, email=email , organisation=admin_data[1], admin_id=admin_data[0], role='user')
                    new_user.set_password(password)
                    db.session.add(new_user)
                    db.session.commit()
                    flash('Sign UP successful. Please login.', 'success')
            return redirect(url_for('login_User'))

    return render_template('loginsignupU.html',activesignup='active', css='/static/loginsignupU.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})


@app.route('/login_User', methods=['GET', 'POST'])
def login_User():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        user = UserAuth.query.filter_by(user_id=user_id).first()
        if user and user.check_password(password):
            login_user(user)
            #app.config['SESSION_PERMANENET'] = True   #should i do it here ?
            session['user_id'] = user_id                   #session will be saved with respect to email
            return redirect(url_for('homepage'))
        else:
            return render_template('error.html',msg='Invaild Credentials',link='/login_User')
    return render_template('loginsignupU.html', activelogin='active',css='static/loginsignupU.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/signup_Admin', methods=['GET', 'POST'])
def signup_Admin():
    if request.method == 'POST':
        name = request.form['name']
        admin_id = request.form['admin_id']
        email = request.form['email']
        password1 = request.form['password1']
        password2=request.form['password2']

        with UseDatabase(dbconfig2) as cursor:
            cmd = "SELECT admin_id FROM govauth WHERE admin_id=%s"
            cursor.execute(cmd,(admin_id,))
            admin_data = cursor.fetchall()
        
        if admin_data==None:
            return render_template('error.html',msg='No such admin under goverement',link='/signup_Admin')
        else:
            #unique user id
            existing_admin_id=AdminAuth.query.filter_by(admin_id=admin_id).first()
            if existing_admin_id:
                return render_template('error.html',msg='Admin ID already exists',link='/signup_Admin') 
            else :
                #password match
                if password1 != password2:
                    return render_template('error.html',msg='Password and Confirm password must be same',link='/signup_Admin')
                else :
                    #only unique email
                    existing_email = AdminAuth.query.filter_by(email=email).first()
                    if existing_email:
                        return render_template('error.html',msg='Email already exists',link='/signup_Admin')
                    else:
                        #creating object and inserting object
                        new_admin = AdminAuth(admin_id=admin_id ,organisation=name ,email=email, role='admin')
                        new_admin.set_password(password1)
                        db.session.add(new_admin)
                        db.session.commit()

                        flash('Sign UP successful. Please login.', 'success')
                        return redirect(url_for('login_Admin'))

    return render_template('loginsignupA.html',activesignupA='active', css='/static/loginsignupA.css' , distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/login_Admin', methods=['GET', 'POST'])
def login_Admin():
    if request.method == 'POST':
        admin_id = request.form['admin_id']
        password = request.form['password']
        admin = AdminAuth.query.filter_by(admin_id=admin_id).first()

        if admin and admin.check_password(password):
            login_user(admin)
            #app.config['SESSION_PERMANENET'] = True   #should i do it here ?
            session['admin_id'] = admin_id #session will be saved with respect to user_id
            return redirect(url_for('homepage'))
        else:
            return render_template('error.html',msg='Invalid Credentials',link='/login_Admin')
    return render_template('loginsignupA.html', activeloginA='active',css='/static/loginsignupA.css' , distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})


@app.route('/') #Done
def homepage() -> 'Html page':
    return render_template('homepage.html', activehome='active',css='static/homepagecss.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})   

@app.route('/patient_details')
def patient1() -> 'Html Page':
    return render_template('patient_details.html', activeproduct='active', css='/static/patientcss.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/about_us') 
def about_us() -> 'Html Page':
    return render_template('about_us.html', activeabout='active',css='static/about_uscss.css', distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})

@app.route('/patient_details2', methods=['GET', 'POST'])
def patient2() -> 'Next Deatils of patient':

    name = request.form['name']
    age = request.form['age']
    sex = request.form['sex']
    phoneno = request.form['phoneno']
    aadhar = request.form['aadhar']

    return render_template('patient_details2.html', activeproduct='active', css='/static/patientcss.css', name=name,age=age,sex=sex,phoneno=phoneno,aadhar=aadhar,distosymp_ordered={'test':[[1],'abc', 00, 'testclass']}, )


@app.route('/product/<name>/<age>/<sex>/<phoneno>/<aadhar>', methods=['GET', 'POST'])  #Done
def product(name,age,sex,phoneno,aadhar) -> 'Html Page':

    name = name
    age = int(age)
    sex = sex
    phoneno = phoneno
    aadhar =aadhar
    bloodg = request.form['bloodgroup']
    weight = request.form['weight']
    height = request.form['height']
    bloodp = request.form['bloodpressure']
    bloodsl = request.form['sugar']
    bmi = int(weight)/(float(height)*float(height))
    
    with UseDatabase(dbconfig) as cursor:
        cmd = "SELECT sympname FROM symptoms"
        cursor.execute(cmd)
        symptomslt = cursor.fetchall()

    symptoms = [item for sublist in symptomslt for item in sublist]
    
    return render_template('product.html', activeproduct='active',css='/static/productcss.css', name=name, age=age,sex=sex, phoneno=phoneno, aadhar=aadhar, bloodg=bloodg, weight=weight, height=height, bloodp=bloodp, bloodsl=bloodsl, bmi=bmi,distosymp_ordered={'test':[[1],'abc', 00, 'testclass']}, symptoms=symptoms) 


@app.route('/result1/<name>/<age>/<sex>/<phoneno>/<aadhar>/<bloodg>/<weight>/<height>/<bloodp>/<bloodsl>/<bmi>', methods=['GET', 'POST']) 
def tool1(name,age,sex,phoneno,aadhar,bloodg,weight,height,bloodp,bloodsl,bmi) -> 'Name of Possible Diseases':

    symptom1 = request.form['symptom1']
    symptom2 = request.form['symptom2']
    symptom3 = request.form['symptom3']
    symptom4 = request.form['symptom4']
    symptom5 = request.form['symptom5']
    age = int(age)
    bmi = float(bmi)

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

        count = 0
        for i,j in distosymp_dict.items():
            count = count + len(j[0])


        colors = ['#36a2eb', '#ff6384', '#ff9f40', '#ffcd56', '#22cfcf','#ffcd56','#c9cbcf']
        classnames = ['disbar1', 'disbar2', 'disbar3', 'disbar4', 'disbar5','disbar6','disbar7']
        i = 0
        distosymp_ordered = {}
        for key,value in key_length_pairs:
            distosymp_ordered[key] = distosymp_dict[key]
            percentagef = len(distosymp_dict[key][0])/count * 100
            percentage = round(percentagef, 2)
            distosymp_ordered[key].append(percentage)
            distosymp_ordered[key].append(colors[i])
            distosymp_ordered[key].append(classnames[i])
            i = i+1

        disnameforJS = []
        percentageforJS = []
        for key, value in  distosymp_ordered.items():
            disnameforJS.append(key)
            percentageforJS.append(value[1])

    patient_data = (name, age, disnameforJS[0], bmi, bloodp, bloodsl, sex, phoneno, aadhar, current_user.get_id())

    with UseDatabase(dbconfig2) as cursor:
        cmd = "INSERT INTO phistory(name, age, disease, bmi, bloodp, bloodsl, sex, phoneno, aadhar, user_id) VALUES{}".format(patient_data)
        cursor.execute(cmd)

    return render_template('result1.html', activeproduct='active', css='/static/result1css.css', distosymp_ordered=distosymp_ordered, disnameforJS=disnameforJS, percentageforJS=percentageforJS,name=name,age=age,sex=sex,bloodp=bloodp,bloodsl=bloodsl,bmi=bmi,bloodg=bloodg) 

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
        
        question_sympkeys.append(-1)
        question_sympkeys = tuple(question_sympkeys)    
        cmd = "SELECT question, checks FROM symptodis WHERE sympkey IN {} AND diskey=%s".format(question_sympkeys)
        cursor.execute(cmd,(diskey_tuple[0],))
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

@app.route('/adminProfile')
def adminprofile():

    with UseDatabase(dbconfig) as cursor:
        cmd='SELECT diskey,disname,link FROM disease'
        cursor.execute(cmd)
        diseaselist = cursor.fetchall()

        sympnamelist = []
        for i in diseaselist:
            cursor.execute('SELECT sympkey FROM symptodis where diskey=%s',(i[0],))
            temp1=cursor.fetchall()
            temp1list = list([i[0] for i in temp1])
            temp1list.append(-1)
            temp1tuple=tuple(temp1list)
            cmd = "SELECT sympname FROM symptoms WHERE sympkey IN {}".format(temp1tuple)
            cursor.execute(cmd)
            temp2 = cursor.fetchall()
            temp2tuple = tuple(item for sublist in temp2 for item in sublist)
            print(temp2tuple)
            sympnamelist.append(temp2tuple)

    diseasedata = []
    j=-1
    for i in diseaselist:
        j=j+1
        row = {
        "name":i[1],
        "symptoms":sympnamelist[j],
        "button": "<button type=\"button\" class=\"btn btn-primary\">Update</button>"
        }
        diseasedata.append(row)

    with open('./static/diseases.json', 'w') as f:
        f.truncate()
        json.dump(diseasedata,f,indent=4)

    with UseDatabase(dbconfig2) as cursor:
        cmd = "SELECT admin_id,organisation, email FROM adminauth WHERE admin_id=%s"
        cursor.execute(cmd,(current_user.get_id(),))
        admindata = cursor.fetchone()
        cmd = "SELECT name,user_id,email FROM userauth WHERE admin_id=%s"
        cursor.execute(cmd,(current_user.get_id(),))
        doctors = cursor.fetchall()

    doctordata = []
    for i in doctors:
        row = {
        "doctor_name":i[0],
        "doctor_id":i[1],
        "email":i[2]
        }
        doctordata.append(row)

    with open('./static/doctor.json', 'w') as f1:
        f1.truncate()
        json.dump(doctordata,f1,indent=4)

    return render_template('adminProfile.html', css='./static/adminProfilecss.css', admin_id=admindata[0], email=admindata[2], organisation=admindata[1],distosymp_ordered={'test':[[1],'abc', 00, 'testclass']})


#admin is updating data
@app.route('/add_disease' , methods=['GET','POST'])
def add_disease():
    if request.method == 'POST':
        symp =[[],[],[],[],[]]
        symp[0].append( request.form['symptom1'] )
        symp[0].append( request.form['check1'] )
        symp[0].append(("Are you experiencing %s"%(request.form['symptom1'],)))
        symp[1].append( request.form['symptom2'] )
        symp[1].append( request.form['check2'] )
        symp[1].append(("Are you experiencing %s"%(request.form['symptom2'],)))
        symp[2].append( request.form['symptom3'] )
        symp[2].append( request.form['check3'] )
        symp[2].append(("Are you experiencing %s"%(request.form['symptom3'],)))
        symp[3].append( request.form['symptom4'] )
        symp[3].append( request.form['check4'] )
        symp[3].append(("Are you experiencing %s"%(request.form['symptom4'],)))
        symp[4].append( request.form['symptom5'] )
        symp[4].append( request.form['check5'] )
        symp[4].append(("Are you experiencing %s"%(request.form['symptom5'],)))
        disease = request.form['disease']
        cases=request.form['cases']
        link=request.form['diseaselink']

        with UseDatabase1(dbconfig) as db:
            cmd="SELECT diskey FROM disease WHERE disname=%s" #checking this insted of diskey
            db[0].execute(cmd,(disease,))
            diskey=db[0].fetchone()

            if diskey!=None:  #disease present
                flash("Disease Already In Database ",'error')
            else :
                cmd="INSERT INTO disease (disname,cases,link) VALUES(%s,%s,%s)" #disease inserted
                db[0].execute(cmd,(disease,cases,link,))
                db[1].commit()

                cmd="select diskey from disease where disname =%s"  #diskey key retrived
                db[0].execute(cmd,(disease,))
                diskey=db[0].fetchone()

                for i in symp :
                    cmd="SELECT sympkey FROM symptoms WHERE sympname=%s" #chceking if symp in or not
                    db[0].execute(cmd,(i[0],))
                    sympkey=db[0].fetchone()

                    if sympkey!=None :                                    # symp already present
                        cmd="INSERT INTO symptodis (sympkey,diskey,checks,question) VALUES(%s,%s,%s,%s)"  #mapped
                        db[0].execute(cmd,(sympkey[0],diskey[0],i[1],i[2]))
                        db[1].commit()

                    else :
                        cmd="INSERT INTO symptoms (sympname) VALUES(%s)"   #symp inserted
                        db[0].execute(cmd,(i[0],))
                        db[1].commit()

                        cmd="SELECT sympkey FROM symptoms WHERE sympname=%s"   #simpkey retrived
                        db[0].execute(cmd,(i[0],))
                        sympkey = db[0].fetchone()
                        cmd= "INSERT INTO symptodis(sympkey,diskey,checks,question) values(%s,%s,%s,%s)"    #mapped
                        db[0].execute(cmd,(sympkey[0],diskey[0],i[1],i[2]))

    with UseDatabase(dbconfig) as cursor:
        cmd="SELECT sympname FROM symptoms"
        cursor.execute(cmd)
        symptomslt = cursor.fetchall()

    symptoms = [item for sublist in symptomslt for item in sublist]

    return render_template('addDisease.html', css='/static/addDiseasecss.css',distosymp_ordered={'test':[[1],'abc', 00, 'testclass']},symptoms=symptoms)

@app.route('/add_doctor', methods=["GET", "POST"])
def adddoctor():
    doctorID = request.form['doctorId']

    with UseDatabase(dbconfig2) as cursor:
        cmd = "INSERT INTO govauth(admin_id,user_id,name) VALUES(%s,%s,%s)"
        cursor.execute(cmd,(current_user.get_id(),doctorID,current_user.organisation))

    return redirect('/adminProfile')

@app.route('/userProfile')
def userProfile():

    with UseDatabase(dbconfig2) as cursor:
        cmd = "SELECT dates,name,disease,bmi,age,bloodp,bloodsl FROM phistory WHERE user_id=%s"
        cursor.execute(cmd,(current_user.get_id(),))  
        phistorydata = cursor.fetchall()

    pdata = []
    for i in phistorydata:
        row = {
        "datetime":str(i[0]),
        "name":i[1],
        "disease": i[2],
        "bmi":i[3],
        "age":i[4],
        "bp":i[5],
        "bsl":i[6],
        }
        pdata.append(row)

    with open('./static/patients.json', 'w') as f:
        f.truncate()
        json.dump(pdata,f,indent=4)

    return render_template('userProfile.html',css='/static/userProfilecss.css',user_id=current_user.get_id(),name=current_user.name,email=current_user.email,organisation=current_user.organisation)


app.run(debug=True)