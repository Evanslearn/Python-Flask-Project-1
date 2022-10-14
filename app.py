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
# --- So, render template searches the templates folder, by default
# ---------------------------------------------------------------------------------------
from libraries import *
from forms import *


app = Flask(__name__)  # referencing this file
# app.config['WTF_CSRF_ENABLED'] = False - Tried to suspend these tokens, to post easily in postman
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


# ----------- ----------- FUNCTIONS TO BE USED BELOW, TO AVOID COPY-PASTING CODE ----------- -----------
# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- DELETE SCHEME ----- ----- ----- -----
def delete_scheme(id, className, nameString, url):
    to_delete = className.query.get_or_404(id)

    try:
        db.session.delete(to_delete)
        db.session.commit()
        flash(f"{nameString} Deleted Successfully", category='alert alert-danger')
        return redirect(url)
    except:
        return flash(f"Encountered error while deleting {nameString}", category='alert alert-warning')


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
            flash("Name added successfully", category='alert alert-success')
            #name = request.form["name"]
            #name = request.form.get["name"]
            #form = request.form.get["form"]
            name = request.form["name"]

            new_task = MyTask(name=name)

        try:
            db.session.add(new_task)
            db.session.commit()
            tasks = MyTask.query.order_by(MyTask.date_created).all()
            return redirect('/')
        except:
            #return f'{name}'
            return Response('Encountered an error while adding', status = 204)
    else:
        tasks = MyTask.query.order_by(MyTask.date_created).all()
        return render_template('home.html', tasks=tasks,
                               name = name,
                               form = form)


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
            flash("Name updated successfully", category='alert alert-success')
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
            flash("Address updated successfully", category='alert alert-success')
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
                               form = form)


# ----- ----- ----- ----- DELETE ----- ----- ----- -----
@app.route('/delete/<int:id>')
def delete_task(id):
    delete_scheme(id, MyTask, 'Task', '/')
    return redirect('/')


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

        user = User.query.filter_by(username=username).first()
        # If username exists, we cannot register the new user with said username
        if user is not None:
            my_message = 'This username is already taken. Please select another one.'
            flash(my_message, category='alert alert-danger')
            return redirect('/register/')
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
                    flash("User Registered successfully", category='alert alert-success')
                    return redirect('/login/')
                except:
                    print(f"not found. flag reg = {flag_reg}")
                    return 'Encountered an error while registering'
            else:
                my_message = "The two password fields did not match."
                flash(my_message, category='alert alert-danger')
                return redirect('/register/')

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

                    flash("Access granted to user", category='alert alert-success')
                    return redirect('/profile/')
                else:
                    my_message = "The password does not match this username"
                    flash(my_message, category='alert alert-danger')
                    return redirect('/login/')
            else:
                print(f"not found. flag login = {flag_login}")
                my_message = "Username not found. Please check your spelling, or register."
                flash(my_message, category='alert alert-danger')
                return redirect('/login/')

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
    flash(my_message, 'alert alert-primary')
    flag_login = 1
    return render_template('login.html', flag_login = flag_login, my_message = my_message,
                           form = LoginForm())


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- PROFILE ----- ----- ----- -----
@app.route('/profile/', methods=['POST','GET','PUT'])
@login_required
def profile():
    user = User.query.filter_by(username=current_user.username).first()
    profile_found = Profile.query.filter_by(username=user.username, user=user).first()
    # If we do not find profile entry in profile db, we create the entry

    description = None
    form_description = DescriptionForm()
    mynote = None
    form_note = NoteForm()
    mypost = None
    form_post = PostForm()
    update_mynote = None
    form_updatenote = UpdateNoteForm()

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
            if form_description.validate_on_submit():
                description = form_description.description.data
                form_description.description.data = ''

            try:

                if profile_found:
                    profile_found.description = description
                    db.session.commit()
                    flash("Description Updated", category='alert alert-success')
                    form_description.description.data = 'description'
                    return redirect('/profile/')
                else:
                    profile_add.description = description
                    db.session.add(profile_add)
                    db.session.commit()
                    flash("Description Added", category='alert alert-success')
                    return redirect('/profile/')
            except:
                print("Encountered an error while updating profile information")

        elif 'mynote' in request.form:
            # Validate our form
            if form_note.validate_on_submit():
                mynote = form_note.mynote.data
                form_note.mynote.data = ''

            print(f'My note is : {mynote}')
            newnote = Notes(username=user.username, content=mynote)

            try:

                db.session.add(newnote)
                db.session.commit()
                flash("Note Taken", category='alert alert-success')
                return redirect('/profile/')

            except:
                print('Encountered an error while taking note')

        elif 'mypost' in request.form:
            # Validate our form
            if form_post.validate_on_submit():
                mypost = form_post.mypost.data
                form_post.mypost.data = ''

            print(f'My post is : {mypost}')
            newpost = Posts(username=user.username, content=mypost)

            try:

                db.session.add(newpost)
                db.session.commit()
                flash("Post Shared", category='alert alert-success')
                return redirect('/profile/')

            except:
                print('Encountered an error while posting')


    if request.method == 'PUT':
        print(f"request.form -> {request.form}")

        if profile_found:
            profile_found.note = description
            db.session.commit()
            flash("Description Updated", category='alert alert-success')
            form_description.description.data = 'description'
            return redirect('/profile/')

    id = current_user.id
    description0 = 'null'
    posts = 'null'
    myposts = Posts.query.filter_by(username=user.username).all()
    notes = 'null'
    mynotes = Notes.query.filter_by(username=user.username).all()
    if profile_found:
        id = profile_found.user.id
        if profile_found.description is not None:
            description0 = profile_found.description
            form_description.description.data = description0 # Setting the default value in update description to be our description
    if myposts:
        posts = myposts
    if mynotes:
        notes = mynotes
    return render_template('profile.html', id = id, profile_found = profile_found, description0 = description0, posts = posts, notes = notes,
                           description = description,
                           form_description = form_description,
                           mynote = mynote,
                           form_note = form_note,
                           mypost = mypost,
                           form_post = form_post,
                           update_mynote = update_mynote,
                           form_updatenote = form_updatenote
                           )


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- UPDATE NOTE ----- ----- ----- -----
@app.route('/update/note/<int:id>', methods=['GET','POST','PUT'])
def update(id):
    tempnote = notes.query.get_or_404(id)
    content = tempnote.content
    form = UpdateNoteForm()

    if request.method == 'PUT':
        # Validate our form
        if form.validate_on_submit():
            content = form.content.data
            form.name.data = ''
            flash("Name updated successfully", category='alert alert-success')
        note.content = name

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
# ----- ----- ----- ----- DELETE NOTE ----- ----- ----- -----
@app.route('/notes/delete/<int:id>')
@login_required
def delete_note(id):
    if current_user.username == Notes.query.get_or_404(id).username:
        delete_scheme(id, Notes, 'Note', '/profile/')
    else:
        flash("You are not authorized to delete another user\'s note!", category='alert alert-warning')
    return redirect('/profile/')


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- DELETE POST ----- ----- ----- -----
@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    if current_user.username == Posts.query.get_or_404(id).username:
        delete_scheme(id, Posts, 'Post', '/profile')
    else:
        flash("You are not authorized to delete another user\'s post!", category='alert alert-warning')
    return redirect('/profile/')


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- DELETE USER ----- ----- ----- -----
@app.route('/users/delete/<int:id>')
def delete_user(id):
    delete_scheme(id, User, 'User', '/users/')
    return redirect('/users/')


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- USERS ----- ----- ----- -----
@app.route('/users/', methods=['POST','GET'])
@login_required
def users():
    allusers = User.query.order_by(User.date_created).all()
    return render_template('users.html', allusers=allusers)


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- ADMIN ----- ----- ----- -----
@app.route('/admin', methods=['POST','GET'])
@login_required
def admin():
    id = current_user.id
    if id == 26:
        allusers = User.query.order_by(User.date_created).all()
        return render_template('admin.html', allusers=allusers)
    else:
        flash("You are not the admin...", category='alert alert-warning')
        return redirect('/')


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- TOOLBOX ----- ----- ----- -----
@app.route('/toolbox/')
def toolbox():

    return render_template('toolbox.html')


# ----- ----- ----- ----- ----- ----- ----- -----
# ----- ----- ----- ----- CALCULATOR ----- ----- ----- -----
@app.route('/toolbox/calculator/')
def calculator():

    flash("C\'mon... Do math!", category='alert alert-primary')
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
    profiles = db.relationship('Profile', backref='user')
    # profile_info = relationship("Profile",backref="user")
    # children = relationship("Profile",back_populates="user")
    # children = relationship("Profile")

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
        return '<Profile %r>' % self.id
# profile.user.x -> access to attribute x of user


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.String(250))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)


class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.String(250))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)


class LoginTrace(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique Identifier for each table record (PRIMARY KEY)
    username = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Return string everytime we create new element
    def __repr__(self):
        return '<LoginTrace %r>' % self.id


if __name__ == "__main__":
    app.run(debug=True)
