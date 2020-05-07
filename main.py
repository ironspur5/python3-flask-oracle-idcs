from flask import Flask, render_template, redirect, request, session
import requests
import IdcsClient
import json

app = Flask(__name__)

# secret key is needed for session
app.secret_key = 'secret'


# Definition of the /auth route
@app.route('/auth', methods=['POST', 'GET'])
def auth():

    # Loading the configurations
    options = getoptions()

    # Authentication Manager loaded with the configurations
    am = IdcsClient.AuthenticationManager(options)

    '''
    Using Authentication Manager to generate the Authorization Code URL, passing the
    application's callback URL as parameter, along with code value and code parameter
    '''
    url = am.getAuthorizationCodeUrl(options["redirectURL"], options["scope"], "1234", "code")

    # Redirecting the browser to the Oracle Identity Cloud Service Authorization URL.
    return redirect(url, code=302)

# Function used to load the configurations from the config.json file
def getoptions():
    fo = open("config.json", "r")
    config = fo.read()
    options = json.loads(config)
    return options


# Definition of the /logout route
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    id_token = (session.get("id_token", None))

    options = getoptions()

    url = options["BaseUrl"]
    url += options["logoutSufix"]
    url += '?post_logout_redirect_uri=http%3A//localhost%3A8000&id_token_hint='
    url += id_token

    # clears Flask client-side session (also works on refresh)
    session.clear()

    # Redirect to Oracle Identity Cloud Service logout URL
    return redirect(url, code=302)


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/home', methods=['POST', 'GET'])
def home():

    # first call IDCS API to get id_token; should return 400 status if not authenticated
    # if statement to kick you back to login if status is 400
    # if authenticated, status 200 allows app to render protected html

    options = getoptions()

    # 'code' is authorization code which is needed to get id_token
    # uses flask.request library (different from Python requests library)
    session['code'] = request.args.get('code')

    data = {
        'grant_type': 'authorization_code',
        'code': session['code'],
        'redirect_uri': options['redirectURL']
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }

    response = requests.post(options['BaseUrl'] + '/oauth2/v1/token?', data=data, headers=headers,
                             auth=(options['ClientId'], options['ClientSecret']))

    session['id_token'] = response.json().get("id_token")

    if str(response.status_code) != "200":
        return render_template('login.html')

    return render_template('home.html')


if __name__ == '__main__':
    app.run(port=8000, debug=True)
