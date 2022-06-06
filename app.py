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
    if request.method == 'POST':
        task_name = request.form['name']
        new_task = MyTask(name=task_name)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        except:
            return 'Encountered an error while adding'
    else:
        tasks = MyTask.query.order_by(MyTask.date_created).all()
        return render_template('home.html', tasks=tasks)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- UPDATE NAME ----- ----- ----- -----
@app.route('/update/name/<int:id>', methods=['GET','POST'])
def update(id):
    task = MyTask.query.get_or_404(id)

    if request.method == 'POST':
        task.name = request.form['name']

        try:
            db.session.commit()
            return redirect('/')
        except:
            return "Encountered error while updating"
    else:
        return render_template('update_name.html', task=task)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- UPDATE ADDRESS ----- ----- ----- -----
@app.route('/update/address/<int:id>', methods=['GET','POST'])
def test(id):
    task = MyTask.query.get_or_404(id)

    if request.method == 'POST':
        task.email_address = request.form.get('email_address')

        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'Encountered an error while adding address'
    else:
        return render_template('update_address.html', task=task)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
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
    if request.method == 'POST':
        user_username = request.form.get('username')
        user_password = request.form.get('password')
        user_password_repeat = request.form.get('password_repeat')

        user = User.query.filter_by(username=user_username).first()
        # If username exists, we cannot register the new user with said username
        if user is not None:
            my_message = 'This username is already taken. Please select another one.'
            return render_template('register.html', flag_reg = flag_reg, my_message = my_message)
        # If the username does not already exist
        else:

            # If the 2 password fields match
            if user_password == user_password_repeat:
                new_user = User()
                new_user.username = user_username
                new_user.password = user_password # The hashing is done by our password setter attribute method

                try:
                    db.session.add(new_user)
                    db.session.commit()
                    return redirect('/login/')
                except:
                    print("not found. flag reg =", flag_reg)
                    return 'Encountered an error while registering'
            else:
                my_message = "The two password fields did not match."
                return render_template('register.html', flag_reg = flag_reg, my_message = my_message)
    flag_reg = 0  # We don't want the error message to be displayed on refresh
    print("flag reg= ", flag_reg)
    my_message = "Refreshed register.html"
    return render_template('register.html', flag_reg=flag_reg, my_message = my_message)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- LOGIN ----- ----- ----- -----
@app.route('/login/', methods=['POST','GET'])
def login():
    flag_login = 1  # This is used for showing login error message
    if request.method == 'POST':
        user_username = request.form.get('username')
        user_password = request.form.get('password')

        try:
            # We try to find if the username is registered in our database
            user = User.query.filter_by(username=user_username).first()

            if user is not None:  # If username exists, we should also check the password
                print("User Found. ->", user, "\nProvide the matching password...\n...")

                # If password (when hashed), matches the stored password hash
                if user.verify_password(user_password):

                    # We keep track of which user logged in, and when
                    print("Access granted to ", user)
                    new_login = LoginTrace(username=user_username)
                    db.session.add(new_login)
                    db.session.commit()
                    login_user(user)

                    return redirect('/profile/')
                else:
                    my_message = "The password does not match this username"
                    return render_template('login.html', flag_login = flag_login, my_message = my_message)
            else:
                print("not found. flag login =", flag_login)
                my_message = "Username not found. Please check your spelling, or register."
                return render_template('login.html', flag_login = flag_login, my_message = my_message)

        except:
            print( 'Encountered an error while logging in')
    flag_login = 0  # We don't want the error message to be displayed on refresh
    print("flag login = ",flag_login)
    my_message = "Refreshed login.html"
    return render_template('login.html', flag_login = flag_login, my_message = my_message)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- LOGOUT ----- ----- ----- -----
@app.route('/logout/', methods=['POST','GET'])
@login_required
def logout():
    logout_user()
    my_message = "You have been logged out"
    flag_login = 1
    return render_template('login.html', flag_login = flag_login, my_message = my_message)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- PROFILE ----- ----- ----- -----
@app.route('/profile/', methods=['POST','GET'])
@login_required
def profile():
    user = User.query.filter_by(username=current_user.username).first()
    profile_found = Profile.query.filter_by(username=user.username, user=user).first()
    # If we do not find profile entry in profile db, we create the entry
    if profile_found:
        pass
    else:
        profile_add = Profile(username=user.username, user=user)
        db.session.add(profile_add)
        db.session.commit()

    if request.method == 'POST':
        print(request.form)
        if 'description' in request.form or 'description_update' in request.form:
            profile_description = request.form.get('description_update')
            print('Description: ',request.form.get('description_update'))
            profile_add_description = request.form.get('description')
            print('Description to add: ', request.form.get('description'))

            try:

                if profile_found:
                    profile_found.description = profile_description
                    db.session.commit()
                    # print(profile_found.user.password_hash)      profile_found.user.x -> access to attribute x of user
                    return render_template('profile.html', id = user.id, description0 = profile_found.description)
                else:
                    profile_add.description = profile_add_description
                    db.session.add(profile_add)
                    db.session.commit()
                    return render_template('profile.html', id = user.id, description0 = profile_add.description)
            except:
                print("Encountered an error while updating profile information")
        elif request.form.get('share_post'):
            profile_post = request.form.get('share_post')
            print("My post is : ",profile_post)
            mypost = Posts(username=user.username, content=profile_post)

            try:

                    db.session.add(mypost)
                    db.session.commit()
                    posts = Posts.query.filter_by(username=user.username).all()
                    return render_template('profile.html', id = user.id, description0 = profile_found.description, posts=posts)

            except:
                print("Encountered an error while posting")

    id = current_user.id
    description0 = 'null'
    posts = 'null'
    myposts = Posts.query.filter_by(username=user.username).all()
    if profile_found:
        id = user.id
    if profile_found.description != None:
        description0 = profile_found.description
    if myposts:
        posts = myposts
    print(user)
    return render_template('profile.html', id = id, description0 = description0, posts = posts)  # It knows it's in the template folder


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- USERS ----- ----- ----- -----
@app.route('/users/', methods=['POST','GET'])
@login_required
def users():
    users = User.query.order_by(User.date_created).all()
    return render_template('users.html', users=users)  # It knows it's in the template folder


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
