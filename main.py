from flask import Flask, abort, request
import os
from random import randint
import sqlite3
from base64 import b64encode
from os import urandom
import hashlib

filename = "userdata.db"

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
                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)''')

        # Save (commit) the changes
        connection.commit()

    except:
        init_db()

app = Flask(__name__)

@app.route("/")
def main():
    body = '<a href="/login">Login?</a><br><a href="/register">Register?</a>'
    #var = "".join([random_imgur() for i in range(1)])
    return body

@app.route("/login")
def login():
    body = '<form action="/login_post" method="post">Username: <input type="text" name="username"><br>Password: <input type="password" name="password"><br><input type="submit" value="Submit"></form><br><a href="/">Home?</a><br><a href="/register">Register?</a>'
    #var = "".join([random_imgur() for i in range(1)])
    return body

@app.route("/register")
def register():
    body = '<form action="/register_post" method="post">Username: <input type="text" name="username"><br>Password: <input type="password" name="password"><br>Confirm Password: <input type="password" name="password_confirm"><br><input type="submit" value="Submit"></form><br><a href="/">Home?</a><br><a href="/login">Login?</a>'
    #var = "".join([random_imgur() for i in range(1)])
    return body

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
                    return "Logged in<br><a href='/login'>Logout?</a>"
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
            c.execute("INSERT INTO users(username, password, salt) VALUES (?,?,?)",[username,hashed_password,salt])
        
            # Save (commit) the changes
            connection.commit()

            connection.close()
            return "Registered Successfully<br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
        except:
            connection.close()
            return "Registration Failed<br><a href='/register'>Register?</a><br><a href='/'>Home?</a>"
    else:
        return "Username is taken<br><a href='/register'>Register?</a><br><a href='/login'>Login?</a><br><a href='/'>Home?</a>"
    
    connection.close()

    return "Error<br><a href='/register'>Register?</a><br><a href='/'>Home?</a>"

    

def hash_password(password,salt):
    salted_str = (password+salt).encode("utf-8")
    hashGen = hashlib.sha512()
    hashGen.update(salted_str)
    hashed_password = hashGen.hexdigest()
    return hashed_password

##def oof(i):
##    return "<br><b>"+str(i)+"</b>"
##
##def random_imgur():
##    string = ""
##    for i in range(1000000):
##        string += str(randint(0,1))        
##    return string
##    letters = ["a","b","c","d","e","f","g","h","i","j","k","l","m","m","o","p","q","r","s","t","u","v","w","x","y","z"]
##    numbers = ["0","1","2","3","4","5","6","7","8","9"]
##
##    imgur_str = ""
##    for i in range(10000000):
##        char_type = randint(0,1)
##        if char_type == 1:
##            case = randint(0,1)
##            character = letters[randint(0,len(letters)-1)]
##            if case == 0:
##                character = character.upper()
##        else:
##            character = str(numbers[randint(0,len(numbers)-1)]) #maybe just do a randint next time
##        imgur_str += character
##    return "<br>"+imgur_str
    #return '<br><blockquote class="imgur-embed-pub" lang="en" data-id="a/'+imgur_str+'"><a href="//imgur.com/'+imgur_str+'"></a></blockquote><script async src="//s.imgur.com/min/embed.js" charset="utf-8"></script>'

init()

app.run()


