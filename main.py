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
    print("----------------- def auth() ---------------")
    # Loading the configurations
    options = getOptions()
    print("config.json file = %s" % options)
    # Authentication Manager loaded with the configurations
    am = IdcsClient.AuthenticationManager(options)
    '''
    Using Authentication Manager to generate the Authorization Code URL, passing the
    application's callback URL as parameter, along with code value and code parameter
    '''
    url = am.getAuthorizationCodeUrl(options["redirectURL"], options["scope"], "1234", "code")

    # print(getAccessToken(options['BaseUrl'], options['ClientId'], options['ClientSecret']))

    # Redirecting the browser to the Oracle Identity Cloud Service Authorization URL.
    return redirect(url, code=302)


def getAccessToken(URL, clientId, clientSecret):
    data = {
        'grant_type': 'client_credentials',
        'scope': 'urn:opc:idm:__myscopes__'
    }
    # Request for auth token
    response = requests.post(URL + '/oauth2/v1/token', data=data, verify=False, auth=(clientId, clientSecret))
    # Parses response into JSON format
    res = response.json()
    # Parse access token
    access_token = res['access_token']
    return access_token


# Function used to load the configurations from the config.json file
def getOptions():
    fo = open("config.json", "r")
    config = fo.read()
    options = json.loads(config)
    return options


# Definition of the /logout route
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    code = (session.get("code", None))
    id_token = (session.get("id_token", None))
    print(code)
    print(id_token)

    options = getOptions()

    url = options["BaseUrl"]
    url += options["logoutSufix"]
    url += '?post_logout_redirect_uri=http%3A//localhost%3A8000&id_token_hint='
    url += id_token

    # Redirect to Oracle Identity Cloud Service logout URL
    return redirect(url, code=302)


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/home', methods=['POST', 'GET'])
def home():
    session['code'] = request.args.get('code')

    # Todo: check if code actually is IDCS code and not spoofed fake one (call IDCS API to validate)

    '''
    this check here is so that people cant just 
    go to website like http://www.app.com/home effectively skipping the login authentication route;
    '''
    if session['code'] == 'None':
        return render_template('login.html')

    print(session['code'])
    options = getOptions()

    data = {
        'grant_type': 'authorization_code',
        'code': session['code'],
        'redirect_uri': options['redirectURL']
    }

    print(data['code'])
    print(data['redirect_uri'])

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }

    response = requests.post(options['BaseUrl'] + '/oauth2/v1/token?', data=data, headers=headers,
                             auth=(options['ClientId'], options['ClientSecret']))

    session['id_token'] = response.json().get("id_token")
    print(response.json().get("id_token"))

    return render_template('home.html')


if __name__ == '__main__':
    app.run(port=8000, debug=True)


