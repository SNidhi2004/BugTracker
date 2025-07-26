from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length
from bson.objectid import ObjectId

# === Config ===
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/bugtracker'
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

# === Login Manager ===
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# === User Model ===
class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.name = user_doc['name']
        self.email = user_doc['email']
        self.role = user_doc.get('role', 'Developer')

    @staticmethod
    def from_email(email):
        doc = mongo.db.users.find_one({'email': email})
        return User(doc) if doc else None

    @staticmethod
    def from_id(id):
        doc = mongo.db.users.find_one({'_id': ObjectId(id)})
        return User(doc) if doc else None

@login_manager.user_loader
def load_user(user_id):
    return User.from_id(user_id)

# === WTForms ===
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('Developer', 'Developer'), ('Admin', 'Admin')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# === Routes ===
@app.route('/')
def homepage():
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if mongo.db.users.find_one({'email': form.email.data}):
            flash('Email already registered.')
            return redirect(url_for('register'))
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_id = mongo.db.users.insert_one({
            'name': form.name.data,
            'email': form.email.data,
            'password': pw_hash,
            'role': form.role.data
        }).inserted_id
        user = User.from_id(user_id)
        login_user(user)
        flash('Registration successful. Welcome!')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        doc = mongo.db.users.find_one({'email': form.email.data})
        if doc and bcrypt.check_password_hash(doc['password'], form.password.data):
            user = User(doc)
            login_user(user)
            flash('Login successful.')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('login'))


@app.route('/add_team', methods=['GET', 'POST'])
@login_required
def add_team():
    if current_user.role != 'Admin':
        flash('Only admins may create new teams.')
        return redirect(url_for('dashboard'))
    form = TeamForm()
    if form.validate_on_submit():
        team = {
            "name": form.name.data.strip(),
            "description": form.description.data.strip()
        }
        mongo.db.teams.insert_one(team)
        flash('Team created successfully.')
        return redirect(url_for('dashboard'))
    return render_template('add_team.html', form=form)



# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', name=current_user.name, role=current_user.role)

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     # Find the teammates (same team as current user) or all developers as needed:
#     team_id = getattr(current_user, 'team_id', None)
#     if team_id:
#         teammates = list(mongo.db.users.find({'team_id': team_id}))
#     else:
#         teammates = list(mongo.db.users.find({'role': 'Developer'}))
#     teammate_names = [user['name'] for user in teammates]
#     # Count closed/open bugs for each teammate by name
#     open_counts = []
#     closed_counts = []
#     for user in teammates:
#         open_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Open'})
#         closed_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Closed'})
#         open_counts.append(open_count)
#         closed_counts.append(closed_count)
#     return render_template(
#         'dashboard.html',
#         name=current_user.name,
#         role=current_user.role,
#         teammate_names=teammate_names,
#         open_counts=open_counts,
#         closed_counts=closed_counts
#     )


# class BugForm(FlaskForm):
#     title = StringField('Title', validators=[DataRequired(), Length(min=3, max=200)])
#     description = TextAreaField('Description', validators=[DataRequired()])
#     priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')], default='Low')status = SelectField('Status', choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Closed', 'Closed')], default='Open')
#     assigned_to = SelectField('Assign To', coerce=str)
#     submit = SubmitField('Submit')
    


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     if current_user.role == 'Admin':
#         # For Admin: show team management options + all bugs summary
#         teams = list(mongo.db.teams.find())
#         teammates = list(mongo.db.users.find())  # all users
#         teammate_names = [user['name'] for user in teammates]

#         # Aggregate bug counts by user
#         open_counts = []
#         closed_counts = []
#         for user in teammates:
#             open_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Open'})
#             closed_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Closed'})
#             open_counts.append(open_count)
#             closed_counts.append(closed_count)

#         return render_template(
#             'dashboard_admin.html',
#             name=current_user.name,
#             role=current_user.role,
#             teammate_names=teammate_names,
#             open_counts=open_counts,
#             closed_counts=closed_counts,
#             teams=teams
#         )

#     else:
#         # For developers: show own bugs & team bugs
#         team_id = getattr(current_user, 'team_id', None)
#         if team_id:
#             teammates = list(mongo.db.users.find({'team_id': team_id}))
#         else:
#             teammates = list(mongo.db.users.find({'role': 'Developer'}))
#         teammate_names = [user['name'] for user in teammates]

#         open_counts = []
#         closed_counts = []
#         for user in teammates:
#             open_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Open'})
#             closed_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Closed'})
#             open_counts.append(open_count)
#             closed_counts.append(closed_count)

#         return render_template(
#             'dashboard_dev.html',
#             name=current_user.name,
#             role=current_user.role,
#             teammate_names=teammate_names,
#             open_counts=open_counts,
#             closed_counts=closed_counts
#         )




@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        # For Admin: show team management options + all bugs summary
        teams = list(mongo.db.teams.find())
        teammates = list(mongo.db.users.find())  # all users
        teammate_names = [user['name'] for user in teammates]

        # Aggregate bug counts by user
        open_counts = []
        closed_counts = []
        for user in teammates:
            open_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Open'})
            closed_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Closed'})
            open_counts.append(open_count)
            closed_counts.append(closed_count)

        return render_template(
            'dashboard_admin.html',
            name=current_user.name,
            role=current_user.role,
            teammate_names=teammate_names,
            open_counts=open_counts,
            closed_counts=closed_counts,
            teams=teams
        )

    else:
        # For developers: show own bugs & team bugs
        team_id = getattr(current_user, 'team_id', None)
        if team_id:
            teammates = list(mongo.db.users.find({'team_id': team_id}))
        else:
            teammates = list(mongo.db.users.find({'role': 'Developer'}))
        teammate_names = [user['name'] for user in teammates]

        open_counts = []
        closed_counts = []
        for user in teammates:
            open_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Open'})
            closed_count = mongo.db.bugs.count_documents({'assigned_name': user['name'], 'status': 'Closed'})
            open_counts.append(open_count)
            closed_counts.append(closed_count)

        return render_template(
            'dashboard_dev.html',
            name=current_user.name,
            role=current_user.role,
            teammate_names=teammate_names,
            open_counts=open_counts,
            closed_counts=closed_counts
        )


class BugForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=3, max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    team = SelectField('Team', coerce=str, validate_choice=False)
    assigned_name = StringField('Assigned To (name)', validators=[Length(max=100)])
    status = SelectField('Status', choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Closed', 'Closed')], default='Open')
    assigned_to = SelectField('Assign To', coerce=str)
    submit = SubmitField('Submit')

class TeamForm(FlaskForm):
    name = StringField('Team Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    submit = SubmitField('Create Team')

def get_user_name(user_id):
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return user['name'] if user else 'N/A'


@app.route('/add_bug', methods=['GET', 'POST'])
@login_required
def add_bug():
    form = BugForm()
    teams = list(mongo.db.teams.find())
    form.team.choices = [('', '-- No Team --')] + [(str(team['_id']), team['name']) for team in teams]
    if form.validate_on_submit():
        bug = {
            "title": form.title.data,
            "description": form.description.data,
            "priority": form.priority.data,
            "status": "Open",
            "created_by": current_user.id,
            "assigned_name": form.assigned_name.data.strip(),
            "team_id": form.team.data if form.team.data else None,
            "created_at": datetime.utcnow()
        }
        mongo.db.bugs.insert_one(bug)
        flash('Bug raised!')
        return redirect(url_for('bug_list'))
    return render_template('add_bug.html', form=form)


@app.route('/bugs')
@login_required
def bug_list():
    bugs = list(mongo.db.bugs.find())
    teams = list(mongo.db.teams.find())
    teams_dict = {str(t['_id']): t['name'] for t in teams}
    for bug in bugs:
        bug['created_by_name'] = get_user_name(bug['created_by'])
        bug['team_name'] = teams_dict.get(bug.get('team_id'), '-') if bug.get('team_id') else '-'
    return render_template('bug_list.html', bugs=bugs)


@app.route('/update_bug/<bug_id>', methods=['GET', 'POST'])
@login_required
def update_bug(bug_id):
    bug = mongo.db.bugs.find_one({'_id': ObjectId(bug_id)})
    if not bug:
        flash('Bug not found.')
        return redirect(url_for('bug_list'))
    form = BugForm(data=bug)
    teams = list(mongo.db.teams.find())
    form.team.choices = [('', '-- No Team --')] + [(str(team['_id']), team['name']) for team in teams]
    if current_user.role != 'Admin':
        form.assigned_name.render_kw = {'readonly': True}
        form.team.render_kw = {'disabled': True}
    if form.validate_on_submit():
        update_fields = {
            "title": form.title.data,
            "description": form.description.data,
            "priority": form.priority.data,
        }
        if current_user.role == 'Admin':
            update_fields['assigned_name'] = form.assigned_name.data.strip()
            update_fields['team_id'] = form.team.data if form.team.data else None
        mongo.db.bugs.update_one({'_id': ObjectId(bug_id)}, {"$set": update_fields})
        flash('Bug updated.')
        return redirect(url_for('bug_list'))
    return render_template('update_bug.html', form=form)


@app.route('/delete_bug/<bug_id>', methods=['POST'])
@login_required
def delete_bug(bug_id):
    if current_user.role != "Admin":
        flash('Only admins can delete bugs.')
        return redirect(url_for('bug_list'))
    mongo.db.bugs.delete_one({'_id': ObjectId(bug_id)})
    flash('Bug deleted.')
    return redirect(url_for('bug_list'))


if __name__ == '__main__':
    app.run(debug=True, port = 5001)
