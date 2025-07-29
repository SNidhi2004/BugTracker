from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SelectMultipleField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo , Optional
from bson.objectid import ObjectId
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'devsecretkey'  # Replace with env variable in production
app.config['MONGO_URI'] = 'mongodb+srv://bugtrackeruser:bugtrackeruser1234@myatlasclusteredu.fuxls.mongodb.net/?retryWrites=true&w=majority&appName=myAtlasClusterEDU'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

######### MODELS & USER LOADER #########

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.name = user_doc['name']
        self.email = user_doc['email']
        self.role = user_doc.get('role', 'Developer')
        self.team_id = str(user_doc.get('team_id')) if user_doc.get('team_id') else None

    @staticmethod
    def get_by_email(email):
        user = mongo.db.users.find_one({'email': email})
        return User(user) if user else None

    @staticmethod
    def get_by_id(uid):
        user = mongo.db.users.find_one({'_id': ObjectId(uid)})
        return User(user) if user else None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

######### FORMS #########

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('Developer', 'Developer'), ('Admin', 'Admin')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BugForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    status = SelectField('Status', choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Closed', 'Closed')], default='Open')
    team = SelectField('Team', coerce=str, validate_choice=False)
    assigned_to = SelectField('Assigned To', coerce=str, validators=[Optional()])  # Changed field name for clarity
    submit = SubmitField('Submit')

class TeamForm(FlaskForm):
    name = StringField('Team Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    members = SelectMultipleField('Team Members', coerce=str)
    bugs = SelectMultipleField('Assign Existing Bugs', coerce=str, validators=[])
    submit = SubmitField('Create Team')

######### ROUTES #########

@app.route('/')
def homepage():
    return redirect(url_for('dashboard'))

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        if mongo.db.users.find_one({'email': form.email.data}):
            flash('Email already registered.', 'warning')
            return redirect(url_for('register'))
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_id = mongo.db.users.insert_one({
            'name': form.name.data.strip(),
            'email': form.email.data.strip(),
            'password': pw_hash,
            'role': form.role.data,
            'team_id': None
        }).inserted_id
        user = User.get_by_id(user_id)
        login_user(user)
        flash('Registration successful! Welcome.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user_doc = mongo.db.users.find_one({'email': form.email.data.strip()})
        if user_doc and bcrypt.check_password_hash(user_doc['password'], form.password.data):
            user = User(user_doc)
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

######### DASHBOARD #########

@app.route('/dashboard')
@login_required
def dashboard():
    
    teams = list(mongo.db.teams.find())
    users = list(mongo.db.users.find())
    user_dict = {str(u['_id']): u for u in users}
    for team in teams:
        member_ids = team.get('members', [])
        member_details = []
        for mid in member_ids:
            user = user_dict.get(str(mid))
            if user:
                member_details.append(user)
        team['member_details'] = member_details

    data = dict(
        name=current_user.name,
        role=current_user.role,
        teams=teams
    )

    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    notifications = user_doc.get('notifications', [])
    # Optionally clear notifications after showing
    mongo.db.users.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'notifications': []}})
    # ...pass notifications to the template...
    return render_template('dashboard.html', **data, notifications=notifications)
######### TEAM CREATE #########

@app.route('/add_team', methods=['GET', 'POST'])
@login_required
def add_team():
    if current_user.role != 'Admin':
        flash('Only admins may create new teams.', 'danger')
        return redirect(url_for('dashboard'))
    form = TeamForm()
    users = list(mongo.db.users.find())
    form.members.choices = [(str(u['_id']), u['name']) for u in users]
    bugs = list(mongo.db.bugs.find())
    form.bugs.choices = [(str(b['_id']), b['title']) for b in bugs]
    if form.validate_on_submit():
        team_id = mongo.db.teams.insert_one({
            'name': form.name.data.strip(),
            'description': form.description.data.strip(),
            'members': [ObjectId(uid) for uid in form.members.data]
        }).inserted_id

        # form = TeamForm()
        for bug_id in form.bugs.data:
            mongo.db.bugs.update_one({'_id': ObjectId(bug_id)}, {'$set': {'team_id': team_id}})
        
        for uid in form.members.data:
            mongo.db.users.update_one(
                {'_id': ObjectId(uid)},
                {
                    '$set': {'team_id': team_id},
                    '$push': {'notifications': f'You have been added to team: {form.name.data.strip()}'}
                }
            )

            if current_user.is_authenticated and str(current_user.id) == uid:
                flash(f'You have been added to team: {form.name.data.strip()}', 'info')

        # Also assign team_id to users
        for uid in form.members.data:
            mongo.db.users.update_one({'_id': ObjectId(uid)}, {'$set': {'team_id': team_id}})
        flash('Team created successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_team.html', form=form)

######### REMOVE USER FROM TEAM #########

@app.route('/remove_user_from_team/<team_id>/<user_id>', methods=['POST'])
@login_required
def remove_user_from_team(team_id, user_id):
    if current_user.role != 'Admin':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('dashboard'))
    mongo.db.teams.update_one({'_id': ObjectId(team_id)}, {'$pull': {'members': ObjectId(user_id)}})
    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$unset': {'team_id': ""}})
    flash('User removed from team.', 'success')
    return redirect(url_for('dashboard'))

######### BUG ROUTES #########

@app.route('/add_bug', methods=['GET', 'POST'])
@login_required
def add_bug():
    form = BugForm()

    # Populate team choices
    teams = list(mongo.db.teams.find())
    form.team.choices = [('', '-- No Team --')] + [(str(t['_id']), t['name']) for t in teams]

    # Populate assigned_to choices with users
    users = list(mongo.db.users.find())
    form.assigned_to.choices = [('', '-- Unassigned --')] + [(str(u['_id']), u['name']) for u in users]

    if form.validate_on_submit():
        bug = {
            'title': form.title.data.strip(),
            'description': form.description.data.strip(),
            'priority': form.priority.data,
            'status': 'Open',
            'created_by': current_user.id,
            'team_id': form.team.data if form.team.data else None,
            'assigned_to': form.assigned_to.data if form.assigned_to.data else None,
            'created_at': datetime.utcnow()
        }
        mongo.db.bugs.insert_one(bug)
        flash('Bug reported successfully!', 'success')
        return redirect(url_for('bug_list'))
    return render_template('add_bug.html', form=form)


@app.route('/bugs')
@login_required
def bug_list():
    bugs = list(mongo.db.bugs.find().sort('created_at', -1))
    users = list(mongo.db.users.find())
    user_dict = {str(u['_id']): u['name'] for u in users}
    teams = list(mongo.db.teams.find())
    teams_dict = {str(t['_id']): t['name'] for t in teams}

    for b in bugs:
        b['_id'] = str(b['_id'])
        b['created_by_name'] = user_dict.get(b.get('created_by'), 'N/A')
        b['team_name'] = teams_dict.get(b.get('team_id'), '-') if b.get('team_id') else '-'
        b['assigned_to_name'] = user_dict.get(b.get('assigned_to'), 'Unassigned')
    
    return render_template('bug_list.html', bugs=bugs)


@app.route('/update_bug_status/<bug_id>', methods=['POST'])
@login_required
def update_bug_status(bug_id):
    bug = mongo.db.bugs.find_one({'_id': ObjectId(bug_id)})
    if not bug:
        flash('Bug not found.', 'warning')
        return redirect(url_for('bug_list'))

    # You can customize the allowed statuses or toggle behavior here
    # For example, cycle between "Open" -> "In Progress" -> "Closed"
    current_status = bug.get('status', 'Open')
    if current_status == 'Open':
        new_status = 'In Progress'
    elif current_status == 'In Progress':
        new_status = 'Closed'
    else:
        new_status = 'Open'  # or keep Closed if you want

    mongo.db.bugs.update_one({'_id': ObjectId(bug_id)}, {'$set': {'status': new_status}})
    flash(f'Bug status changed to {new_status}.', 'success')
    return redirect(url_for('bug_list'))

@app.route('/update_bug/<bug_id>', methods=['GET', 'POST'])
@login_required
def update_bug(bug_id):
    bug = mongo.db.bugs.find_one({'_id': ObjectId(bug_id)})
    if not bug:
        flash('Bug not found.', 'warning')
        return redirect(url_for('bug_list'))

    form = BugForm(data=bug)
    teams = list(mongo.db.teams.find())
    form.team.choices = [('', '-- No Team --')] + [(str(t['_id']), t['name']) for t in teams]

    # Compute selected team name for display (read-only in template)
    selected_team_name = ''
    if form.team.data:
        for val, label in form.team.choices:
            if val == form.team.data:
                selected_team_name = label
                break

    # Only admin can change assigned_name, status, or team
    if current_user.role != 'Admin':
        form.assigned_name.render_kw = {'readonly': True}
        form.status.render_kw = {'disabled': True}
        form.team.render_kw = {'disabled': True}

    if form.validate_on_submit():
        update_data = {
            'title': form.title.data.strip(),
            'description': form.description.data.strip(),
            'priority': form.priority.data,
        }
        if current_user.role == 'Admin':
            update_data.update({
                'assigned_name': form.assigned_name.data.strip(),
                'status': form.status.data,
                'team_id': form.team.data if form.team.data else None
            })
        mongo.db.bugs.update_one({'_id': ObjectId(bug_id)}, {'$set': update_data})
        flash('Bug updated successfully.', 'success')
        return redirect(url_for('bug_list'))

    return render_template('update_bug.html', form=form, selected_team_name=selected_team_name)

@app.route('/delete_bug/<bug_id>', methods=['POST'])
@login_required
def delete_bug(bug_id):
    if current_user.role != 'Admin':
        flash('Only admins can delete bugs.', 'danger')
        return redirect(url_for('bug_list'))
    mongo.db.bugs.delete_one({'_id': ObjectId(bug_id)})
    flash('Bug deleted successfully.', 'success')
    return redirect(url_for('bug_list'))


if __name__ == '__main__':
    app.run(debug=True)
