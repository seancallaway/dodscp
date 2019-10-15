from flask import Flask, render_template, redirect, url_for, request, session, flash, g, Markup
from functools import wraps
from subprocess import check_output
from hashlib import sha256
from uuid import uuid4
import sqlite3


app = Flask(__name__)

app.config.from_object('config')
app.database = app.config['DATABASE']
app.script = app.config['SCRIPT']
app.secret_key = app.config['SECRET_KEY']

###################################### NON-PAGE FUNCTIONS ###################################


def login_required(f):
    """Login required decorator"""
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You must be logged in to view this page.')
            return redirect(url_for('login'))
    return wrap


def admin_required(f):
    """Admin required decorator"""
    @wraps(f)
    def wrap(*args, **kwargs):
        if is_admin(session['uid']):
            return f(*args, **kwargs)
        else:
            flash('You must be an administrator to view that page.')
            return redirect(url_for('home'))
    return wrap


def connect_db():
    """
    Connects to the database

    :return: active database connection
    """
    return sqlite3.connect(app.database)


def check_login(login, password):
    """
    Validates a user login attempt.

    :param login: the username to check
    :param password: the password to check
    :return: True if the login is valid. Otherwise, False
    """
    if login == '' or password == '':
        return False
    else:
        g.db = connect_db()
        cur = g.db.execute('SELECT salt FROM users WHERE login = "' + login + '"')
        salt = cur.fetchone()
        if salt:
            salted = password + salt[0]
        else:
            #unsalted password or invalid login
            g.db.close()
            return False
        hashed = sha256(salted.encode()).hexdigest()
        cur = g.db.execute('SELECT id FROM users WHERE login = "' + login + '" AND password = "' + hashed + '"')
        uid = cur.fetchone()
        g.db.close()
        if uid:
            return uid[0]
        else:
            return False


def change_password(login, password):
    """
    Changes a user's password

    :param login: the username of the account to modify
    :param password: the new password
    """
    salt = uuid4().hex
    hashed = sha256(password.encode() + salt.encode()).hexdigest()

    g.db = connect_db()
    cur = g.db.execute('UPDATE users SET password=?, salt=? WHERE login=?', (hashed, salt, login))
    g.db.commit()
    g.db.close()


def change_admin(login, status=0):
    """
    Modifies a user's admin status

    :param login: the username of the account to modify
    :param status: 1 for admin. 0 for normal user
    """
    g.db = connect_db()
    cur = g.db.execute('UPDATE users SET isAdmin=? WHERE login=?', (status, login))
    g.db.commit()
    g.db.close()


def create_user(login, password, isAdmin=0):
    """
    Create a new user account.

    :param login: the username of the account to create
    :param password: the password for the account
    :param isAdmin: 1 for admin. 0 for normal user
    """
    salt = uuid4().hex
    hashed = sha256(password.encode() + salt.encode()).hexdigest()

    g.db = connect_db()
    cur = g.db.execute('INSERT INTO users(login, password, salt, isAdmin) VALUES (?,?,?,?)', (login, hashed, salt, isAdmin))
    g.db.commit()
    g.db.close()

def is_admin(uid):
    """
    Checks to see if the user is an admin

    :param uid: the user ID of the account to check
    :return: True if admin. Otherwise, False.
    """
    g.db = connect_db()
    cur = g.db.execute('SELECT isADMIN FROM users WHERE id=' + str(uid))
    result = cur.fetchone()
    if result[0] > 0:
        return True
    return False


def get_login(uid):
    """
    Converts a UID into a username.

    :param uid: the user ID to convert
    :return: the username for the user ID provided
    """
    g.db = connect_db()
    cur = g.db.execute('SELECT login FROM users WHERE id=' + str(uid))
    result = cur.fetchone()
    return result[0]


def get_uid(login):
    """
    Converts a username into a user ID

    :param login: the username to convert
    :return: the user ID for the username provided
    """
    g.db = connect_db()
    cur = g.db.execute('SELECT id FROM users WHERE login= "' + login + '"')
    result = cur.fetchone()
    return result[0]


def user_exists(login):
    """
    Checks to see if the username exists in the database.

    :param login: the username to check
    :return: True if exists. Otherwise, False.
    """
    g.db = connect_db()
    cur = g.db.execute('SELECT id FROM users WHERE login= "' + login + '"')
    if len(cur.fetchall()) > 0:
        return True
    return False


def log_action(uid, action):
    """
    Logs a user action to the database.

    :param uid: the ID of the user performing the action.
    :param action: the action being performed.
    """
    
    # ACTIONS
    #1|Successful login
    #2|Failed login
    #3|Logout
    #4|Server started
    #5|Server restarted
    #6|Server stopped
    #7|Server updated
    #8|Reset Own Password
    #9|Reset Anothers Password
    #10|Created User
    #11|Deleted User
    #12|Modified Admin Status

    g.db = connect_db()
    cur = g.db.execute('INSERT INTO loggedactions(user, action, time) VALUES (?,?,datetime("now"))', (uid, action))
    g.db.commit()
    g.db.close()


####################################### PAGE FUNCTIONS ######################################

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    """The index page."""
    results = '';
    if request.method == 'POST':
        if request.form['action'] == 'start':
            # run the start command
            results = "Starting the server...<br /><br />"
            results += check_output([app.script, "start"])
            log_action(session['uid'], 4)
            results = Markup(results.replace('\n', '<br />'))
        elif request.form['action'] == 'stop':
            # run the stop action
            results = "Stoping the server...<br /><br />"
            results += check_output([app.script, "stop"])
            log_action(session['uid'], 6)
            results = Markup(results.replace('\n', '<br />'))
        elif request.form['action'] == 'restart':
            # run the restart action
            results = "Restarting the server...<br /><br />"
            results += check_output([app.script, "restart"])
            log_action(session['uid'], 5)
            results = Markup(results.replace('\n', '<br />'))
        elif request.form['action'] == 'update':
            # run the update action
            results = "Updating the server...<br /><br />"
            results += check_output([app.script, "update"])
            log_action(session['uid'], 7)
            results = Markup(results.replace('\n', '<br />'))
        else:
            # invalid action!
            results = "INVALID ACTION!"

    g.db = connect_db()
    cur = g.db.execute('SELECT time, (SELECT users.login FROM users WHERE users.id = loggedactions.user), actions.action FROM loggedactions LEFT JOIN actions ON loggedactions.action = actions.id ORDER BY time DESC LIMIT 10;')
    actions = [dict(time=row[0], user=row[1], action=row[2]) for row in cur.fetchall()]
    g.db.close()
    return render_template('index.html', actions=actions, results=results, acp=session['priv'], username=session['username'])


@app.route('/welcome')
def welcome():
    """The welcome page."""
    return render_template('welcome.html', username=session['username'])


@app.route('/login', methods=['GET', 'POST'])
def login():
    """The login page."""
    error = None
    if request.method == 'POST':
        uid = check_login(request.form['username'], request.form['password'])
        if not uid:
            error = 'Invalid credentials. Please try again.'
            login = request.form['username']
            if user_exists(login):
                log_action(get_uid(login), 2)
        else:
            session['logged_in'] = True
            session['uid'] = uid
            session['username'] = request.form['username']
            session['priv'] = is_admin(uid)
            log_action(session['uid'], 1)
            flash('You were just logged in.')
            return redirect(url_for('home'))
        #if request.form['username'] != 'ADMIN' or request.form['password'] != 'ADMIN':
        #    error = 'Invalid Credentials. Please try again.'
        #else:
        #    session['logged_in'] = True
        #    flash('You were just logged in.')
        #    return redirect(url_for('home'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """The logout page."""
    log_action(session['uid'], 3)
    session.pop('logged_in', None)
    session.pop('uid', None)
    session.pop('priv', None)
    session.pop('username', None)
    flash('You were just logged out.')
    return redirect(url_for('home'))


@app.route('/changepass', methods=['GET', 'POST'])
@login_required
def change_pass():
    """The change password page."""
    if request.method == 'POST':
        # process password change
        if request.form['pass1'] == request.form['pass2']:
            change_password(session['username'], request.form['pass1'])
            log_action(session['uid'], 8)
            session.pop('logged_in', None)
            session.pop('uid', None)
            session.pop('priv', None)
            session.pop('username', None)
            flash('Your password has been changed. Please login using your new password.')
            return redirect(url_for('home'))
        else:
            flash('The passwords you entered do not match. Please try again.')
            return render_template('changepass.html')
    return render_template('changepass.html')


@app.route('/edituser', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user():
    """The edit user page."""
    if request.method == 'POST':
        if request.form['step'] == "1":
            # select the user and show edit fields
            login = get_login(request.form['user'])
            return render_template('edituser.html', userselected=True, user=login, acp=session['priv'], username=session['username'])
        elif request.form['step'] == "2":
            # change user
            login = request.form['username']
            if request.form['pass1'] != "":
                if request.form['pass1'] == request.form['pass2']:
                    print(f"Changing password for {login} to {request.form['pass1']}")
                    change_password(login, request.form['pass1'])
                    log_action(session['uid'], 9)
                    admin = 0
                    if request.form['status'] == 'admin':
                        admin = 1
                    change_admin(login, admin)
                    log_action(session['uid'], 12)
                    flash('The user has been updated.')
                    return redirect(url_for('edit_user'))
                else:
                    flash('The passwords you entered do not match. Please try again.')
                    return render_template('edituser.html', userselected=True, user=login, acp=session['priv'], username=session['username'])
            else:
                # no password entered. Just change status.
                admin = 0
                if request.form['status'] == 'admin':
                    admin = 1
                change_admin(login, admin)
                log_action(session['uid'], 12)
                flash('The user has been updated.')
                return redirect(url_for('edit_user'))
            return render_template('edituser.html', acp=session['priv'], username=session['username'])
                    
    g.db = connect_db()
    cur = g.db.execute('SELECT id, login FROM users WHERE login != "ADMIN"')
    users = [dict(uid=row[0], login=row[1]) for row in cur.fetchall()]
    g.db.close()
    return render_template('edituser.html', users=users, acp=session['priv'], username=session['username'])


@app.route('/logs')
@login_required
@admin_required
def logs():
    """The log viewing page."""
    g.db = connect_db()
    cur = g.db.execute('SELECT time, (SELECT users.login FROM users WHERE users.id = loggedactions.user), actions.action FROM loggedactions LEFT JOIN actions ON loggedactions.action = actions.id ORDER BY time DESC LIMIT 50;')
    actions = [dict(time=row[0], user=row[1], action=row[2]) for row in cur.fetchall()]
    g.db.close()
    return render_template('logs.html', actions=actions, acp=session['priv'], username=session['username'])


@app.route('/adduser', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    """The add user page."""
    if request.method == 'POST':
        if request.form['pass1'] == request.form['pass2']:
            if not user_exists(request.form['username']):
                # create the user
                admin = 0
                if request.form['status'] == 'admin':
                    admin = 1
                create_user(request.form['username'], request.form['pass1'], admin)
                log_action(session['uid'], 10)
                flash(request.form['username'] + ' has been created.')
                return render_template('adduser.html', acp=session['priv'], username=session['username'])
            else:
                flash('The username you entered is already in use.')
                return render_template('adduser.html', acp=session['priv'], username=session['username'])
        else:
            flash('The passwords you entered do not match. Please try again.')
            return render_template('adduser.html', acp=session['priv'], username=session['username'])
    return render_template('adduser.html', acp=session['priv'], username=session['username'])


if __name__ == '__main__':
    app.run(debug=True)
