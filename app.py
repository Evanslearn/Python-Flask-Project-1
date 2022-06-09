# ---------------------------------------------------------------------------------------
# pip3 install virtualenv
# env\Scripts\activate (Windows)  ---  source 'env\Scripts\activate.bat' (Linux)
# .ls kai cd gia na pame se fakelo project
# virtualenv env
# pip3 install flask flask-sqlalchemy
# localhost:5000 (se chrome, klp?)
# from app import db
# db.create_all() (den epiase se emena me terminal. To evala se @app.before_first_request
# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
# by default, flask searches for these folders:
#   templates (html go here)
#   static (css and javascript go here)
# thus, we followed this convention in this program folders' structure
# ---------------------------------------------------------------------------------------
from libraries import *
from forms import *


app = Flask(__name__)  # referencing this file
app.config['SECRET_KEY'] = "mysecretkeymbinationisamysterforyou"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'  # The database URI that will be used for the connection.

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


db = SQLAlchemy(app)  # DB initialized with settings from app


# ----- ----- ----- ----- ----- ----- ----- -----
#  ----- ----- Create the Database ----- ----- ----- -----
@app.before_first_request
def create_tables():
    db.create_all()


# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #
# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- HOME ----- ----- ----- -----
@app.route('/', methods=['POST','GET'])
def home():
    name = None
    form = NameForm()

    if request.method == 'POST':
        # Validate our form
        if form.validate_on_submit():
            name = form.name.data
            form.name.data = ''
            flash("Name added successfully")
        #task_name = request.form['name']
        new_task = MyTask(name=name)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        except:
            return 'Encountered an error while adding'
    else:
        tasks = MyTask.query.order_by(MyTask.date_created).all()
        return render_template('home.html', tasks=tasks,
                               name = name,
                               form = form)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- UPDATE NAME ----- ----- ----- -----
@app.route('/update/name/<int:id>', methods=['GET','POST'])
def update(id):
    task = MyTask.query.get_or_404(id)
    name = None
    form = NameForm()

    if request.method == 'POST':
        # Validate our form
        if form.validate_on_submit():
            name = form.name.data
            form.name.data = ''
        task.name = name

        try:
            db.session.commit()
            return redirect('/')
        except:
            return "Encountered error while updating"
    else:
        return render_template('update_name.html', task=task,
                               name = name,
                               form = form)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- UPDATE ADDRESS ----- ----- ----- -----
@app.route('/update/address/<int:id>', methods=['GET','POST'])
def test(id):
    task = MyTask.query.get_or_404(id)
    address = None
    form = AddressForm()

    if request.method == 'POST':
        # Validate our form
        if form.validate_on_submit():
            address = form.address.data
            form.address.data = ''
        task.email_address = address
        #task.email_address = request.form.get('email_address')

        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'Encountered an error while adding address'
    else:
        return render_template('update_address.html', task=task,
                               address = address,
                               form = form)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
# Tring to make a blueprint for deleting db enties (task, user, etc)
#def delete(MyClass, id, url):
#    entry_to_delete = MyClass.query.get_or_404(id)
#
#    try:
#        db.session.delete(entry_to_delete)
#        db.session.commit()
#        return redirect(url)
#    except:
#        return "Encountered error while deleting", MyClass
#    delete(MyTask, id, '/')
# ----- ----- ----- ----- DELETE ----- ----- ----- -----
@app.route('/delete/<int:id>')
def delete_task(id):
    task_to_delete = MyTask.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return "Encountered error while deleting task"


# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #
# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- REGISTER ----- ----- ----- -----
@app.route('/register/', methods=['POST','GET'])
def register():
    flag_reg = 1  # This is used for showing login error message
    username = None
    password = None
    password_repeat = None
    form = RegisterForm()

    if request.method == 'POST':

        # Validate our form
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            password_repeat = form.password_repeat.data
            form.username.data = ''
            form.password.data = ''
            form.password_repeat.data = ''

        #user_username = request.form.get('username')
        #user_password = request.form.get('password')
        #user_password_repeat = request.form.get('password_repeat')

        user = User.query.filter_by(username=username).first()
        # If username exists, we cannot register the new user with said username
        if user is not None:
            my_message = 'This username is already taken. Please select another one.'
            return render_template('register.html', flag_reg = flag_reg, my_message = my_message,
                                   username=username,
                                   password=password,
                                   password_repeat=password_repeat,
                                   form=form)
        # If the username does not already exist
        else:

            # If the 2 password fields match
            if password == password_repeat:
                new_user = User()
                new_user.username = username
                new_user.password = password # The hashing is done by our password setter attribute method

                try:
                    db.session.add(new_user)
                    db.session.commit()
                    return redirect('/login/')
                except:
                    print(f"not found. flag reg = {flag_reg}")
                    return 'Encountered an error while registering'
            else:
                my_message = "The two password fields did not match."
                return render_template('register.html', flag_reg = flag_reg, my_message = my_message,
                                       username=username,
                                       password=password,
                                       password_repeat=password_repeat,
                                       form=form)
    flag_reg = 0  # We don't want the error message to be displayed on refresh
    print(f"flag reg= {flag_reg}")
    my_message = "Refreshed register.html"
    return render_template('register.html', flag_reg=flag_reg, my_message = my_message,
                           username = username,
                           password = password,
                           password_repeat = password_repeat,
                           form = form)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- LOGIN ----- ----- ----- -----
@app.route('/login/', methods=['POST','GET'])
def login():
    flag_login = 1  # This is used for showing login error message
    username = None
    password = None
    form = LoginForm()

    if request.method == 'POST':

        # Validate our form
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            form.username.data = ''
            form.password.data = ''

            #user_username = request.form.get('username')
            #user_password = request.form.get('password')

        try:
            # We try to find if the username is registered in our database
            user = User.query.filter_by(username=username).first()

            if user is not None:  # If username exists, we should also check the password
                print(f"User Found. -> {user}.\nProvide the matching password...\n...")

                # If password (when hashed), matches the stored password hash
                if user.verify_password(password):

                    # We keep track of which user logged in, and when
                    print(f"Access granted to {user}")
                    new_login = LoginTrace(username=username)
                    db.session.add(new_login)
                    db.session.commit()
                    login_user(user)

                    return redirect('/profile/')
                else:
                    my_message = "The password does not match this username"
                    return render_template('login.html', flag_login = flag_login, my_message = my_message,
                                           username = username,
                                           password = password,
                                           form = form)
            else:
                print(f"not found. flag login = {flag_login}")
                my_message = "Username not found. Please check your spelling, or register."
                return render_template('login.html', flag_login = flag_login, my_message = my_message,
                                       username = username,
                                       password = password,
                                       form = form)

        except:
            print('Encountered an error while logging in')
    flag_login = 0  # We don't want the error message to be displayed on refresh
    print(f"flag login = {flag_login}")
    my_message = "Refreshed login.html"
    return render_template('login.html', flag_login = flag_login, my_message = my_message,
                           username = username,
                           password = password,
                           form = form)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- LOGOUT ----- ----- ----- -----
@app.route('/logout/', methods=['POST','GET'])
@login_required
def logout():
    logout_user()
    my_message = "You have been logged out"
    flag_login = 1
    return render_template('login.html', flag_login = flag_login, my_message = my_message,
                           form = LoginForm())


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- PROFILE ----- ----- ----- -----
@app.route('/profile/', methods=['POST','GET'])
@login_required
def profile():
    user = User.query.filter_by(username=current_user.username).first()
    profile_found = Profile.query.filter_by(username=user.username, user=user).first()
    # If we do not find profile entry in profile db, we create the entry

    description = None
    form = DescriptionForm()
    myshare = None
    form1 = PostForm()

    if profile_found:
        pass
    else:
        profile_add = Profile(username=user.username, user=user)
        db.session.add(profile_add)
        db.session.commit()

    if request.method == 'POST':
        print(f"request.form -> {request.form}")

        if 'description' in request.form:

            # Validate our form
            if form.validate_on_submit():
                description = form.description.data
                form.description.data = ''

            try:

                if profile_found:
                    profile_found.description = description
                    db.session.commit()
                    return render_template('profile.html', id = user.id, description0 = profile_found.description,
                                           description = description,
                                           form = form,
                                           myshare = myshare,
                                           form1 = form1)
                else:
                    profile_add.description = description
                    db.session.add(profile_add)
                    db.session.commit()
                    return render_template('profile.html', id = user.id, description0 = profile_add.description,
                                           description = description,
                                           form = form,
                                           myshare = myshare,
                                           form1 = form1)
            except:
                print("Encountered an error while updating profile information")
        elif 'myshare' in request.form:

            # Validate our form
            if form1.validate_on_submit():
                myshare = form1.myshare.data
                form1.myshare.data = ''

            #profile_post = request.form.get('share_post')
            print(f'My post is : {myshare}')
            mypost = Posts(username=user.username, content=myshare)

            try:

                db.session.add(mypost)
                db.session.commit()
                posts = Posts.query.filter_by(username=user.username).all()
                return redirect('/profile/')
                #return render_template('profile.html', id = user.id, description0 = profile_found.description, posts=posts,
                 #                      description = description,
                #                       form = form,
                 #                      myshare = myshare,
                #                       form1 = form1)

            except:
                print('Encountered an error while posting')
        """"""

    id = current_user.id
    description0 = 'null'
    posts = 'null'
    myposts = Posts.query.filter_by(username=user.username).all()
    if profile_found:
        id = user.id
    if profile_found.description is not None:
        description0 = profile_found.description
    if myposts:
        posts = myposts
    print("hello")
    return render_template('profile.html', id = id, description0 = description0, posts = posts,
                           description = description,
                           form = form,
                           myshare = myshare,
                           form1 = form1)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- USERS ----- ----- ----- -----
@app.route('/users/', methods=['POST','GET'])
@login_required
def users():
    allusers = User.query.order_by(User.date_created).all()
    return render_template('users.html', allusers=allusers)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- DELETE USER ----- ----- ----- -----
@app.route('/users/delete/<int:id>')
def delete_user(id):
    user_to_delete = User.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect('/users/')
    except:
        return "Encountered error while deleting user"


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- TOOLBOX ----- ----- ----- -----
@app.route('/toolbox/')
def toolbox():

    return render_template('toolbox.html')


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- CALCULATOR ----- ----- ----- -----
@app.route('/toolbox/calculator/')
def calculator():

    return render_template('calculator.html')


# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #
class MyTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique Identifier for each table record (PRIMARY KEY)
    name = db.Column(db.String(50), nullable=False)
    email_address = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Return string everytime we create new element
    def __repr__(self):
        return '<Task %r>' % self.id


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # Unique Identifier for each table record (PRIMARY KEY)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    #profile_info = relationship("Profile",backref="user")
    #children = relationship("Profile",back_populates="user")
    #children = relationship("Profile")
    profiles = db.relationship('Profile', backref='user')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):  # Does this hash go with this password?
        return check_password_hash(self.password_hash, password)

    # Return string everytime we create new element
    def __repr__(self):
        return '<User %r>' % self.id


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique Identifier for each table record (PRIMARY KEY)
    username = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    #parent = relationship("User",back_populates="children")

    # Return string everytime we create new element
    def __repr__(self):
        return '<User %r>' % self.id
# profile.user.x -> access to attribute x of user

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.String(250))


class LoginTrace(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique Identifier for each table record (PRIMARY KEY)
    username = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Return string everytime we create new element
    def __repr__(self):
        return '<User %r>' % self.id


if __name__ == "__main__":
    app.run(debug=True)
