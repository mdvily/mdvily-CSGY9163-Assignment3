from flask import Flask, request, make_response, session, redirect, url_for, escape, render_template
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt
import subprocess, secrets

##Reference: http://www.rmunn.com/sqlalchemy-tutorial/tutorial.html
from sqlalchemy import *
#Set up SQLalchemy database parameters
db = create_engine('sqlite:///spellcheckwebapp.db')
metadata = MetaData(db)
users = Table('users', metadata, autoload=True)
queries = Table('queries', metadata, autoload=True)
iu = users.insert() #Create insert method for users table
iq = queries.insert() #Create insert method for queries table

USER = 'testtest' #set global variable USER

app = Flask(__name__)
#app.secret_key = 'lkkljafovlnkadflkjweoirls413dkl342'
#app.config["SECRET_KEY"] = "lkkljafovlnkadflkjweoirls413dkl342"
app.config["SECRET_KEY"] = secrets.token_urlsafe(16)

#use built-in CSRF protection from Flask-WTF extention
#reference: https://flask-wtf.readthedocs.io/en/stable/csrf.html
csrf = CSRFProtect(app)

#define a dictionary structure to hold active (registered) users
active_users = {}

@app.after_request
def add_security_headers(response):
#Set content security policy in response headers by using the after_request decorator
#in Flask. Reference: https://pythonise.com/series/learning-flask/python-before-after-request
#and https://stackoverflow.com/questions/29464276/add-response-headers-to-flask-web-app
    response.headers['Content-Security-Policy']='default-src \'self\'; script-src \'self\''
#Set x-frame-options header in the response to prevent 'clickjacking' - a class of attacks where clicks
#in the outer frame can be translated invisibly to clicks on your page’s elements.
# Reference: https://flask.palletsprojects.com/en/1.1.x/security/
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
#Force the browser to honor the response content type instead of trying to detect it,
#which can be abused to generate a cross-site scripting (XSS) attack.
#Reference: https://flask.palletsprojects.com/en/1.1.x/security/
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    if 'username' in session:
        username = session['username']
        return render_template('loggedin_base.html', username=username)
    else:
        return render_template(('base.html'))

#If a user accesses the /register site (i.e. using the HTTP GET method, he/she will be presented with a webform prompting them to register
#When the user submits the required information (i.e. using the HTTP POST method, the user's username, password
#and 2-factor authentication information will be stored and passed to a function to register the new user
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        username = str(escape(request.form['uname'])) #Escape username input, because username is later displayed to client in HTML
        #convert the password user submitted into a password hash so that it is not stored in plaintext
        #Reference: https://pythonprogramming.net/password-hashing-flask-tutorial/
        password_hash = sha256_crypt.encrypt(request.form['pword'])
        phone = request.form['2fa']
        return register_user(username, password_hash, phone)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['uname']
        password = request.form['pword']
        phone = request.form['2fa']
        return check_auth(username, password, phone)

def register_user(username, password_hash, phone):
    su = users.select(users.c.username == username)  # Create select method for users table
    rs = su.execute()
    record = rs.fetchone()
    #if username in active_users:

    #Check to see if a user record with this username already exists
    if record is not None:
        return render_template('username_not_available.html', username = username)
    else:
        #active_users[username] = [password_hash, phone]
        iu.execute(username=username, password=password_hash, twofa=phone)
        return render_template('registration_success.html', username = username)

def check_auth(username, password, phone):
    su = users.select(users.c.username == username)
    rs = su.execute()
    record = rs.fetchone()
    #if username not in active_users:
    if record is None:
        #direct user to registration form if username does not exist
        return render_template('auth_failure.html')
    #username exists, which means user registered and password and phone fields are non-empty
    else:
        #Compare the submitted password with the user's stored password hash
        #if sha256_crypt.verify(password, active_users[username][0]):
        if sha256_crypt.verify(password, record.password):
            #if phone == active_users[username][1]:
            if phone == record.twofa:
                #reference: https://www.tutorialspoint.com/flask/flask_sessions.htm
                session['username'] = username
                response = make_response('''
                <html>
                <head>
                    <title>Login Success</title>
                    </head>
                    <body>
                    <h1 id="result">Authentication success.</h1>
                    <h2>You can now use the spell check program</h2>
                    <p><a href="/spell_check">Spell check</a></p>
                    <p><a href="/history">See query history</a></p>
                    <p><a href="/logout">Log out</a></p>
                    </body>
                </html>
                ''')
                return response
            else:
                return render_template('auth_failure.html')
        else:
            return render_template('auth_failure.html')

@app.route('/spell_check', methods=['POST', 'GET'])
def spell_check():
    if 'username' in session:
        if request.method == 'GET':
            return render_template('spellcheck.html')
        elif request.method == 'POST':
            fp = open('text_submission.txt', 'w')
            fp.write(str(escape(request.form['inputtext'])))
            fp.close()
            submitted_text = str(escape(request.form['inputtext'])) #Escaping here is actually unnecessary since the render_template() function does this automatically
            result = subprocess.check_output(["./a.out", "text_submission.txt", "wordlist.txt"]).decode("utf-8").strip().replace('\n', ', ')
            #Select the user record matching the currently logged in user from the users table
            su = users.select(users.c.username == session['username'])
            rsu = su.execute()
            record = rsu.fetchone()
            #Insert the record with the query and response into the query table, matching on the user ID from the users table
            iq.execute(user_id=record.id, query=submitted_text, response=result)
            return render_template('response.html', submitted_text = submitted_text, result = result)
    else:
        return render_template('login_failure.html')

@app.route('/history', methods=['POST', 'GET'])
def history():
    if request.method == 'GET':
        if 'username' in session:
            if session['username'] == 'admin':
                return render_template('admin.html')
            else:
                user = session['username']
                return user_query_history(user)
        else:
            return render_template('login_failure.html')
    elif request.method == 'POST':
        user = request.form['uname']
        su = users.select(users.c.username == user)
        rs = su.execute()
        record = rs.fetchone()
        if record is None:
            resp = '''
            <html>
                <head>
                    <title>No such user</title>
                    </head>
                    <body>
                    <h1>This user does not exist</h1>
                    <p><a href="/spell_check">Spell check</a></p>
                    <p><a href="/history">User query history</a></p>
                    <p><a href="/logout">Log out</a></p>
                    </body>
                </html>
            '''
            return resp
        else:
            return user_query_history(user)

def user_query_history(user):
    USER = user #set global variable to use in the display_query() function
    su = users.select(users.c.username == user)
    rsu = su.execute()
    record = rsu.fetchone()
    sq = queries.select(queries.c.user_id == record.id)
    rsq = sq.execute()
    query_records = rsq.fetchall()
    resp = '''
                <html>
                <head>
                <title>History</title>
                </head>
                <body>
                <h1>Query history for user: ''' + USER + '''</h1><br>
                <p id="numqueries">Total number of queries made: ''' + str(len(query_records)) + '</p><br>'
    for row in query_records:
        resp = resp + '<p id="query' + str(row.query_id) + '"><a href="/history/query' + str(row.query_id) + '">Query' + str(row.query_id) + '</a></p>'
    resp = resp + '''
                <br><br><p><a href="/logout">Log out</a></p>
                </body>
                </html>
                '''
    return resp

@app.route('/history/query<query_id>')
def display_query(query_id):
    sq = queries.select(queries.c.query_id == query_id)
    rsq = sq.execute()
    record = rsq.fetchone()
    return render_template('query_display.html', query_id = query_id, query = record.query, response = record.response)



#Log out user and delete session cookie
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect((url_for('index')))

if __name__ == "__main__":
    app.run(debug=True)


