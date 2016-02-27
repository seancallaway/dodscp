from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps

app = Flask(__name__)

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

####################################### PAGE FUNCTIONS ######################################

#
# INDEX PAGE
#
@app.route('/')
@login_required
def home():
    return render_template('index.html')

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
        if request.form['username'] != 'ADMIN' or request.form['password'] != 'ADMIN':
            error = 'Invalid Credentials. Please try again.'
        else:
            session['logged_in'] = True
            flash('You were just logged in.')
            return redirect(url_for('home'))
    return render_template('login.html', error=error)

#
# LOGOUT PAGE
#
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were just logged out.')
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)
