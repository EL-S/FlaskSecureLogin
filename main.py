from flask import Flask, abort, request, session, redirect, url_for, escape, request
import os
from random import randint
import sqlite3
from base64 import b64encode
from os import urandom
import hashlib
from send_email import *

filename = "userdata.db"

app = Flask(__name__)

app.secret_key = b'' #a secret key to encrypt user sessions

admin_email = "email@gmail.com" #a gmail email address

admin_password = "password" #a gmail email address password

def init():
    global filename
    
    exists = os.path.exists(filename)
    
    if exists: #check file isn't empty or corrupted
        with open(filename, "rb") as file:
            data = file.read()
        if data == b"": #file is empty
            init_db()
    else:
        init_db()

def init_db():
    global filename
    
    try:
        with open(filename, "w") as file:
                file.write("")
        
        connection = sqlite3.connect('userdata.db')

        c = connection.cursor()

        # Create table
        c.execute('''CREATE TABLE users
                    (user_id INTEGER PRIMARY KEY,
                     username varchar(32) NOT NULL,
                     password varchar(128) NOT NULL,
                     salt varchar(128) NOT NULL,
                     confirmation varchar(128) NOT NULL,
                     email varchar(128) NOT NULL,
                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)''')

        # Save (commit) the changes
        connection.commit()

    except:
        init_db()

@app.route("/")
def index():
    if logged_in():
        try:
            username = session.get("username")
            return 'Ya boi '+username+' logged in<br><a href="/settings">Settings?</a><br><a href="/logout">Log out?</a>'
        except:
            body = '<a href="/login">Login?</a><br><a href="/register">Register?</a>'
            return body
    else:
        body = '<a href="/login">Login?</a><br><a href="/register">Register?</a>'
        return body

@app.route("/login")
def login():
    body = '<form action="/login_post" method="post">Username: <input type="text" name="username"><br>Password: <input type="password" name="password"><br><input type="submit" value="Submit"></form><br><a href="/">Home?</a><br><a href="/register">Register?</a>'
    #var = "".join([random_imgur() for i in range(1)])
    return body

@app.route("/register")
def register():
    body = '<form action="/register_post" method="post">Username: <input type="text" name="username"><br>Password: <input type="password" name="password"><br>Confirm Password: <input type="password" name="password_confirm"><br>Email: <input type="text" name="email"><br><input type="submit" value="Submit"></form><br><a href="/">Home?</a><br><a href="/login">Login?</a>'
    #var = "".join([random_imgur() for i in range(1)])
    return body

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))    

@app.route('/login_post', methods=['POST']) 
def login_post():
    if not request.form:
        abort(400)

    username = request.form.get('username')
    password = request.form.get('password')

    connection = sqlite3.connect('userdata.db')
    
    try:
        c = connection.cursor()
        
        c.execute("SELECT password,salt FROM users WHERE username=?", [username])
        rows = c.fetchall()

        if rows:
            try:
                hashed_password = rows[0][0]
                salt = rows[0][1]
                hashed_password_attempt = hash_password(password,salt)

                if hashed_password == hashed_password_attempt:
                    #create cookie and redirect to secure pages
                    session['username'] = username
                    return redirect(url_for('index'))
                else:
                    return "Incorrect Password<br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
            except:
                return "Error Logging In<br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
        else:
            return "User does not exist<br><a href='/register'>Register?</a><br><a href='/'>Home?</a>"
    except:
        return "Error<br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"

@app.route('/register_post', methods=['POST']) 
def register_post():
    if not request.form:
        abort(400)
    salt = b64encode(os.urandom(96)).decode("utf-8") #the 96 bytes is 128 characters in base64
    username = request.form.get('username')
    password = request.form.get('password')
    password_confirm = request.form.get('password_confirm')
    email = request.form.get('email')
    validation_code = b64encode(os.urandom(12)).decode("utf-8").replace("=","a").replace("+","b").replace("/","c")

    connection = sqlite3.connect('userdata.db')

    c = connection.cursor()

    c.execute("SELECT username FROM users WHERE username=?", [username])

    rows = c.fetchall()

    if not rows: #username does not already exist
        if password == password_confirm:
            hashed_password = hash_password(password,salt)
        else:
            return "Passwords must match<br><a href='/register'>Register?</a><br><a href='/'>Home?</a>"
        
        # Insert a row of data
        try:
            c.execute("INSERT INTO users(username, password, salt, confirmation, email) VALUES (?,?,?,?,?)",[username,hashed_password,salt,validation_code,email])
        
            # Save (commit) the changes
            connection.commit()

            connection.close()

            confirmation_link = "<a href='http://127.0.0.1:5000/confirm_email?cc="+validation_code+"&user="+username+"'>Click here to complete your registration.</a>"
            
            email_status = send_email(admin_email,admin_password,email,"Confirmation Email",confirmation_link)
            
            if email_status:
                return "Registered Successfully!<br><br>Please use the confirmation link in your email for full access (The email may be in your spam folder).<br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
            else:
                return "Registered mostly successfully!<br><br>The confirmation link failed to send to your email, for full access, change your email or retry the sending process when you log in.<br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
        except:
            connection.close()
            return "Registration Failed<br><a href='/register'>Register?</a><br><a href='/'>Home?</a>"
    else:
        return "Username is taken<br><a href='/register'>Register?</a><br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
    
    connection.close()

    return "Error<br><a href='/register'>Register?</a><br><a href='/'>Home?</a>"

@app.route('/settings') 
def settings():
    #if the email isn't confirmed, resend the email
    #ability to change the password and the email
    if logged_in():
        resend_email = ''
        try:
            username = session.get("username")
            
            connection = sqlite3.connect('userdata.db')
            
            c = connection.cursor()
                
            c.execute("SELECT confirmation FROM users WHERE username=?", [username])

            rows = c.fetchall()

            if rows: #the username does exist

                validation_code = rows[0][0]

                if validation_code != "y": #potentially bad as it reveals the users email is confirmed
                    resend_email = '<br><a href="/resend_email">Resend Confirmation Email?</a>'
                else:
                    pass
            else:
                return 'What in tarnation.'
        except:
            return 'Something went wrong.'
        return 'Ya logged in and on the settings page<br><a href="/">Home?</a>'+resend_email+'<br><a href="/logout">Log out?</a>'
    else:
        return redirect(url_for('index'))

#todo

#change email

#change password

#change username(?)

#I forgot my password

#I forgot my username

#I forgot my email

@app.route('/resend_email')
def resend_email():
    if 'username' in session:
        #now check the database if that is a real username
        
        try:
            username = session.get("username")
            
            connection = sqlite3.connect('userdata.db')
            
            c = connection.cursor()
                
            c.execute("SELECT confirmation,email FROM users WHERE username=?", [username])

            rows = c.fetchall()

            if rows: #the username does exist

                validation_code = rows[0][0]
                email = rows[0][1]

                if validation_code == "y": #potentially bad as it reveals the users email is confirmed
                    return "That email has already been confirmed."
                else:
                    confirmation_link = "<a href='http://127.0.0.1:5000/confirm_email?cc="+validation_code+"&user="+username+"'>Click here to complete your registration.</a>"
                            
                    email_status = send_email(admin_email,admin_password,email,"Confirmation Email",confirmation_link)

                    if email_status:
                        return 'Email sent successfully.'
                    else:
                        return 'The email was not sent successfully.'
            else:
                return 'What in tarnation.'
        except:
            return 'Something went wrong.'
    else:
        return 'You must be logged in to do this.'

@app.route("/confirm_email", methods={'GET'})
def confirm_email(): #have the code expire
    try:
        confirmation_code = request.args.get("cc")
        username = request.args.get("user")
        try:
            
            connection = sqlite3.connect('userdata.db')
            
            c = connection.cursor()
                
            c.execute("SELECT confirmation FROM users WHERE username=?", [username])

            rows = c.fetchall()

            if rows: #the username does exist
                print(rows)
                confirmation_code_real = rows[0][0]
                if confirmation_code_real == "y": #potentially bad as it reveals the users email is confirmed
                    return "That email has already been confirmed"
                elif confirmation_code_real == confirmation_code:
                    #update the entry to be 'y'
                    c.execute("UPDATE users SET confirmation=? WHERE username=?", ['y',username])

                    connection.commit()
                    
                    connection.close()
                    
                    return "Your email has been validated."
                else:
                    return "Invalid Code."
            else:
                return "Invalid Username."
        except:
            return "Invalid Attempt."
    except:
        return "Invalid."
    #do a lookup to check if that confirmation code matches that username

    #if it do, redirect to homepage

    #else, go to a page to send a new confirmation code (when logged in)

def logged_in():
    if 'username' in session:
        #now check the database if that is a real username
        
        try:
            username = session.get("username")
            
            connection = sqlite3.connect('userdata.db')
            
            c = connection.cursor()
                
            c.execute("SELECT username FROM users WHERE username=?", [username])

            rows = c.fetchall()

            if rows: #the username does exist
                return True
            else:
                return False
        except:
            return False
    else:
        return False

def confirmation_email(): #maybe work on this later
    #get a validation code
    validation_code = b64encode(os.urandom(32)).decode("utf-8")
    print(validation_code)
    #store it in the db with the user
    #email the code with a link

def hash_password(password,salt):
    salted_str = (password+salt).encode("utf-8")
    hashGen = hashlib.sha512()
    hashGen.update(salted_str)
    hashed_password = hashGen.hexdigest()
    return hashed_password

init()

app.run()


