from datetime import datetime as dt
import csv
import string
import socket
import re
from passlib.hash import sha256_crypt
from flask import Flask, redirect, url_for, render_template, request, session, flash

PASSWORD_FILE = 'passfile.csv'
app = Flask(__name__)
app.secret_key = 'supersecretkey'
FILENAME = 'failedlogins.txt'

def ipaddress():
    hostname = socket.gethostname()
    ipaddr = socket.gethostbyname(hostname)
    return ipaddr != '192.168.1.166'  # Change to your IP or remove if needed

def checkPassword(password):
    """Checks if the password is in the Common Password document"""
    with open('CommonPassword.txt', 'r') as file:
        for line in file:
            if re.search(password, line, re.I):
                return True
    return False

def check_complexity(pass_str):
    """Ensures password meets complexity requirements"""
    length = len(pass_str) >= 12
    lowercase = any(c in string.ascii_lowercase for c in pass_str)
    uppercase = any(c in string.ascii_uppercase for c in pass_str)
    numbers = any(c in string.digits for c in pass_str)
    spec_char = any(c in string.punctuation for c in pass_str)
    return length and lowercase and uppercase and numbers and spec_char

@app.route('/')
@app.route('/home/')
def home():
    """Renders the home page"""
    mydate = dt.now()
    mydate_formated = mydate.strftime("%m-%d-%Y %H:%M:%S")
    article_title = 'Python Flask Website'
    article_content = 'Welcome to my website. You can register and login using the nav bar above.'
    return render_template(
        "home.html",
        style='home',
        pagename='Home',
        article_title=article_title,
        article_content=article_content,
        authenticated='user' in session,
        mydate_formated=mydate_formated
    )

@app.route('/register/', methods=['POST', 'GET'])
def register():
    """Handles registration requests"""
    if request.method == 'GET':
        return render_template('register.html', style='home', pagename='Registration')

    username = request.form['username']
    password = request.form['password']

    if len(username) < 4:
        flash('Username must be a minimum of 4 characters long.')
        return redirect(url_for('register'))

    if getPasswordIfRegistered(username) is not None:
        flash('This username already exists.')
        return redirect(url_for('register'))

    if checkPassword(password):
        flash('Password is too common.')
        return redirect(url_for('register'))

    if not check_complexity(password):
        flash('Password must be a minimum of 12 characters long and contain at least 1 lowercase, 1 uppercase, 1 special, and 1 number character.')
        return redirect(url_for('register'))

    write_user_to_file(username, password)
    flash('Registered successfully!')
    return redirect(url_for('login'))

def write_user_to_file(username, password):
    """Writes user information to the file"""
    pass_hash = sha256_crypt.hash(password)
    try:
        with open(PASSWORD_FILE, 'a', newline='') as passFile:
            writer = csv.writer(passFile)
            writer.writerow([username, pass_hash])
    except Exception as e:
        print(f"Error writing to file {PASSWORD_FILE}: {e}")
        flash('Account database is not reachable at this time. Try back later or contact support.')
        return redirect(url_for('register'))

def failedlogins():
    """Logs failed login attempts"""
    ipaddr = socket.gethostbyname(socket.gethostname())
    with open(FILENAME, "a") as f:
        f.write(f"{dt.now().strftime('%Y-%m-%d %H:%M')} -- {ipaddr}\n")

@app.route('/login/', methods=['POST', 'GET'])
def login():
    """Handles login requests"""
    if request.method == 'GET':
        return render_template('login.html', style='home', pagename='Login')

    username = request.form['username']
    password = request.form['password']
    storedPassword = getPasswordIfRegistered(username)

    if ipaddress():
        flash('Wrong IP address')
        failedlogins()
        return render_template('login.html')

    if storedPassword is None:
        flash('Username does not exist.')
        failedlogins()
        return render_template('login.html')

    if sha256_crypt.verify(password, storedPassword):
        session['user'] = username
        flash(f'Welcome {username.title()}!')
        return render_template('welcome.html', authenticated='user' in session)
    
    flash('Login failed due to incorrect password.')
    failedlogins()
    return redirect(url_for('login'))

def getPasswordIfRegistered(username_input):
    """Retrieves the password hash for the given username"""
    try:
        with open(PASSWORD_FILE, "r") as users:
            for record in users:
                if len(record) == 0:
                    continue
                username, password = record.strip().split(',')
                if username == username_input:
                    return password
    except Exception as e:
        print(f"Error reading file {PASSWORD_FILE}: {e}")
        flash('Account database is not reachable at this time. Try back later or contact support.')
        return redirect(url_for('home'))
    return None

@app.route('/passwordupdate/', methods=['POST', 'GET'])
def passwordupdate():
    """Handles password update requests"""
    if request.method == 'GET':
        return render_template('passwordupdate.html', style='home', pagename='Change Password')

    username = request.form['username']
    password = request.form['password']
    newpassword = request.form['newpassword']
    confirmnewpassword = request.form['confirmnewpassword']

    storedPassword = getPasswordIfRegistered(username)
    if storedPassword is None:
        flash('Username does not exist.')
        return redirect(url_for('passwordupdate'))

    if newpassword == password:
        flash('New password cannot be your old password.')
        return redirect(url_for('passwordupdate'))

    if newpassword != confirmnewpassword:
        flash('New password and confirm new password must be the same.')
        return redirect(url_for('passwordupdate'))

    if checkPassword(newpassword):
        flash('Password is too common.')
        return redirect(url_for('passwordupdate'))

    if not check_complexity(newpassword):
        flash('New password must be a minimum of 12 characters long and contain at least 1 lowercase, 1 uppercase, 1 special, and 1 number character.')
        return redirect(url_for('passwordupdate'))

    update_user_password(username, newpassword)
    flash('Password changed successfully!')
    return redirect(url_for('login'))

def update_user_password(username_input, newpassword):
    """Updates the user's password in the file"""
    temp_file = 'temp_passfile.csv'
    with open(PASSWORD_FILE, 'r') as infile, open(temp_file, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        updated = False
        for row in reader:
            if row[0] == username_input:
                writer.writerow([username_input, sha256_crypt.hash(newpassword)])
                updated = True
            else:
                writer.writerow(row)
        if not updated:
            writer.writerow([username_input, sha256_crypt.hash(newpassword)])
    # Replace the old file with the updated one
    import os
    os.replace(temp_file, PASSWORD_FILE)

@app.route('/logout/')
def logout():
    """Logs the user out"""
    session.pop('user', None)
    flash('Logged out successfully!')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run()
