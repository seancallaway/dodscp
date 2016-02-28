from flask import Flask, render_template, redirect, url_for, request, session, flash, g, Markup
from functools import wraps
from subprocess import check_output
from hashlib import sha256
from uuid import uuid4
import sqlite3


app = Flask(__name__)

app.database = "dodscp.db"
app.script = "/home/sean/dodsserver"

# TODO: Move and replace this.
app.secret_key = "OgV@DeND@qywQ@pIvh4l@qFifyb"

###################################### NON-PAGE FUNCTIONS ###################################

##
# Login Required Decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You must be logged in to view this page.')
            return redirect(url_for('login'))
    return wrap

##
# SQLite Database Connector
# Returns the db connection.
def connect_db():
    return sqlite3.connect(app.database)

##
# Check login
#
def check_login(login, password):
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

##
# Create user
def create_user(login, password, isAdmin=0):
    salt = uuid4().hex
    hashed = sha256(password.encode() + salt.encode()).hexdigest()

    g.db = connect_db()
    cur = g.db.execute('INSERT INTO users(login, password, salt, isAdmin) VALUES (?,?,?,?)', (login, hashed, salt, isAdmin))
    g.db.commit()
    g.db.close()

##
# Is the user an admin?
def is_admin(uid):
    g.db = connect_db()
    cur = g.db.execute('SELECT isADMIN FROM users WHERE id=?', uid)
    result = cur.fetchone()
    if result[0] > 0:
        return True
    return False

####################################### PAGE FUNCTIONS ######################################

#
# INDEX PAGE
#
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    results = '';
    if request.method == 'POST':
        if request.form['action'] == 'start':
            # run the start command
            results = "Starting the server...<br /><br />"
            results += check_output([app.script, "start"])
            results = Markup(results.replace('\n', '<br />'))
        elif request.form['action'] == 'stop':
            # run the stop action
            results = "Stoping the server...<br /><br />"
            results += check_output([app.script, "stop"])
            results = Markup(results.replace('\n', '<br />'))
        elif request.form['action'] == 'restart':
            # run the restart action
            results = "Restarting the server...<br /><br />"
            results += check_output([app.script, "restart"])
            results = Markup(results.replace('\n', '<br />'))
        elif request.form['action'] == 'update':
            # run the update action
            results = "Updating the server...<br /><br />"
            results += check_output([app.script, "update"])
            results = Markup(results.replace('\n', '<br />'))
        else:
            # invalid action!
            results = "INVALID ACTION!"

    g.db = connect_db()
    cur = g.db.execute('SELECT time, (SELECT users.login FROM users WHERE users.id = loggedactions.user), actions.action FROM loggedactions LEFT JOIN actions ON loggedactions.action = actions.id ORDER BY time DESC LIMIT 10;')
    actions = [dict(time=row[0], user=row[1], action=row[2]) for row in cur.fetchall()]
    g.db.close()
    return render_template('index.html', actions=actions, results=results)

#
# WELCOME PAGE
#
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

#
# LOGIN PAGE
#
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uid = check_login(request.form['username'], request.form['password'])
        if uid == False:
            error = 'Invalid credentials. Please try again.'
        else:
            session['logged_in'] = True
            session['uid'] = uid
            session['priv'] = is_admin(uid)
            flash('You were just logged in.')
            return redirect(url_for('home'))
        #if request.form['username'] != 'ADMIN' or request.form['password'] != 'ADMIN':
        #    error = 'Invalid Credentials. Please try again.'
        #else:
        #    session['logged_in'] = True
        #    flash('You were just logged in.')
        #    return redirect(url_for('home'))
    return render_template('login.html', error=error)

#
# LOGOUT PAGE
#
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('uid', None)
    session.pop('priv', None)
    flash('You were just logged out.')
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)
