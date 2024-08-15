"""
SDEV 300
Lab 8
Addition to lab 7 project
"""
from datetime import datetime as dt
import csv
import string
import socket
import re
import pandas as pd
from passlib.hash import sha256_crypt
from flask import Flask, redirect, url_for, render_template, request, session, flash

df=pd.read_csv('passfile.csv')

PASSWORD_FILE = 'passfile.csv'
app = Flask(__name__)
app.secret_key = 'supersecretkey'
FILENAME = 'failedlogins.txt'

def ipaddress():
    hostname=socket.gethostname()
    ipaddr=socket.gethostbyname(hostname)
    if ipaddr != '192.168.1.166': #change to your IP
        return True
    return False


def checkPassword(password):
    "checks if the password you chose is in the Common Password document"
    file = open('CommonPassword.txt', 'r')
    for line in file.readlines():
        if re.search(password, line, re.I):
            return True
    return False

def check_complexity(pass_str):
    """Function ensures registered password meets required complexity.
	this code comes from the "secrets" reading from week #2 that should have also been used in lab#2
	"""
    length = bool(len(pass_str) >= 12)
    lowercase = any(c in string.ascii_lowercase for c in pass_str)
    uppercase = any(c in string.ascii_uppercase for c in pass_str)
    numbers = any(c in string.ascii_lowercase for c in pass_str)
    spec_char = any(c in string.punctuation for c in pass_str)
    return bool(length and lowercase and uppercase and numbers and spec_char)

@app.route('/')
@app.route('/home/')
def home():
    """Function calls the 'home.html' template and passes information to render the Home page.
    Routes for the Home page are '/' or '/home/'."""
    mydate = dt.now()
    mydate_formated = mydate.strftime("%Y-%m-%d %H:%M:%S")
    article_title = 'SDEV 300 Lab 7'
    article_content = 'Welcome to my website. In this site, you will have to log in to view all \
of the different information. If you do not have an account, you can register with us today.'
    return render_template(
        "home.html",
        style = 'home',
        pagename = 'Home',
        article_title = article_title,
        article_content = article_content,
        authenticated = bool('user' in session),
        mydate_formated=mydate_formated)

@app.route('/register/', methods = ['POST', 'GET'])
def register():
    """Function calls the register.html template and processes registration requests by
    validating that input meets required standards."""
    if request.method == 'GET':  #get / render the registration page for the user
        return render_template('register.html', style = 'home', pagename = 'Registration')

    username = request.form['username']
    password = request.form['password']

    # Ensure username is a somewhat reasonable length
    if len(username) < 4:
        flash('Username must be a minimum of 4 characters long.')
        return redirect(url_for('register'))

    if getPasswordIfRegistered(username) != None:
        #Do: flash a message saying username already exists
        flash('This username already exists.')
        return render_template('register.html')

    if checkPassword(password) is True:
        flash('Does not meet SP 800-63B criteria')
        return redirect(url_for('register'))

    if not check_complexity(request.form['password']): # Enforce password complexity
        #Do: flash a message telling the user the password rules the password must follow
        flash('Password must be a minimum of 12 characters long and contain at ' \
            'least 1 lowercase, 1 uppercase, 1 special, and 1 number character.')
        return redirect(url_for('register'))

    write_user_to_file(username, password)
    #Do: flash a message telling the user the registration was successful
    flash('Registered successfully!')
    return redirect(url_for('login'))

def write_user_to_file(username, password):
    pass_hash = sha256_crypt.hash(password) #encrypt password before storing to file
    try: # Add account info to account database
        with open(PASSWORD_FILE, 'a', newline='') as passFile:
            writer = csv.writer(passFile)
            writer.writerow([username, pass_hash])
        return
    except FileNotFoundError as e:
        print("Could not find file called " + PASSWORD_FILE)
        print(e.args) #all info about the error printed to the server for support to see/debug
        flash('Account database is not reachable at this time. Database may be missing.')
        return redirect(url_for('register'))
    except Exception as e:
        print("Could not append to file " + PASSWORD_FILE)
        print(e.args) #all info about the error printed to the server for support to see/debug
        flash('Account database is not reachable at this time. Insufficient permissions.')
        return redirect(url_for('register'))

def failedlogins():
    "Logger for failed attempts, posts the time and ip address in failedlogins.txt"
    hostname=socket.gethostname()
    ipaddr=socket.gethostbyname(hostname)
    f = open(FILENAME, "a")
    f.write("{0} -- {1}\n".format(dt.now().strftime("%Y-%m-%d %H:%M"), ipaddr))
    f.close()

@app.route('/login/', methods = ['POST', 'GET'])
def login():
    "Function calls the login.html template and processes login requests."
    # Bring up login page for regular navigation request
    if request.method == 'GET': # get / render the login page for the user
        return render_template('login.html', style = 'home', pagename = 'Login')

    #else request.method == 'POST' so process user inputs from the login page
    username = request.form['username']
    password = request.form['password']
    storedPassword = getPasswordIfRegistered(username)

    if ipaddress() is True:
        flash('Wrong IP address')
        failedlogins()
        return render_template('login.html')

    if storedPassword == None:
        flash('Username does not exist.')
        failedlogins()
        return render_template('login.html')

    try:
        if sha256_crypt.verify(password, storedPassword):
            session['user'] = username
            flash('Welcome ' + username.title() + '!')
            return redirect(url_for('home'))
    except Exception as e:
        print("Could not verify input password of:\n" + password + "\nmatchesstored hashed password of :\n" + storedPassword)
        print("Error info:")
        print(e.args)
        flash('This application is not available at this time. Please try back later or contact support.')
        failedlogins()
        return redirect(url_for('home'))
    #else is implicit if reached this line of code
    flash('Login failed due to incorrect password.')
    failedlogins()
    return redirect(url_for('login'))

def getPasswordIfRegistered(username_input):
    ''' Check if the given username does not already exist in our password file
        return none of the username does not exist; otherwise return the password for that user
    '''
    try:
        with open(PASSWORD_FILE, "r") as users:
            for record in users:
                if len(record) == 0:
                    print('password file is empty')
                    return None
                username, password = record.split(',')
                password = password.rstrip('\n')
                if username == username_input:
                    return password
    except FileNotFoundError as e:
        print('File not found: ' + PASSWORD_FILE)
        print(e.args)
        #flash a message to the user the account database isn’t available right now and try back later or contact support
        flash('Account database is not reachable at this time. Try back later or report issue to support.')
        return redirect(url_for('home'))

    except Exception as e:
        print('No permissions to open this file or data in it not in correct format: ' + PASSWORD_FILE)
        print(e.args)
        #flash a message to the user the account database isn’t available right now and try back later or contact support
        flash('Account database is not reachable at this time. Try back later or report issue to support.')
        return redirect(url_for('home'))
        #decided better to do above than this abort: os.abort()
    return None

def getPasswordIfRegistered2(username_input, newpassword):
    ''' Check if the given username does not already exist in our password file
        return none of the username does not exist; otherwise return the password for that user
    '''
    try:
        with open(PASSWORD_FILE, 'r') as passfile:
            reader = csv.reader(passfile, delimiter = ',')
            for row in reader:
                if len(row) == 0:
                    print('password file is empty')
                    return None
                username_in_file = row[0]
                if username_input == username_in_file:
                    df = df[:-1]
                    password = newpassword
                    password = password.rstrip("\n")
                    write_user_to_file(username_input, password)
                    return password
    except FileNotFoundError as e:
        print('File not found: ' + PASSWORD_FILE)
        print(e.args)
        flash('Account database is not reachable at this time. Try back later or report issue to support.')
        return redirect(url_for('home'))

    except Exception as e:
        print('No permissions to open this file or data in it not in correct format: ' + PASSWORD_FILE)
        print(e.args)
        flash('Account database is not reachable at this time. Try back later or report issue to support.')
        return redirect(url_for('home'))
        #decided better to do above than this abort: os.abort()
    return None

@app.route('/passwordupdate/', methods = ['POST', 'GET'])
def passwordupdate():
    "docstring"
    if request.method == 'GET':
        return render_template('passwordupdate.html', style = 'home', pagename = 'Change Password')

    username = request.form['username']
    password = request.form['password']
    newpassword = request.form['newpassword']
    confirmnewpassword = request.form['confirmnewpassword']

    storedPassword = getPasswordIfRegistered(username)
    if storedPassword == None:
        flash('Username does not exist.')
        return redirect(url_for('passwordupdate'))

    if password == newpassword:
        flash('New password cannot be your old password.')
        return redirect(url_for('passwordupdate'))

    if newpassword != confirmnewpassword:
        flash('New password and confirm new password must be the same password.')
        return redirect(url_for('passwordupdate'))

    checkPassword(password)

    if not check_complexity(request.form['newpassword']): # Enforce password complexity
        #Do: flash a message telling the user the password rules the password must follow
        flash('New Password must be a minimum of 12 characters long and contain at ' \
            'least 1 lowercase, 1 uppercase, 1 special, and 1 number character.')
        return redirect(url_for('passwordupdate'))

    getPasswordIfRegistered2(username, newpassword)

    write_user_to_file(username, password)
    #Do: flash a message telling the user the password change was successful
    flash('Password changed successfully!')
    return redirect(url_for('login'))

@app.route('/logout/')
def logout():
    "Function logs the user out of their session and returns to the Home page."
    session.pop('user', None)
    flash('Logged out successfully!')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run()