from flask import Flask, render_template, session, redirect, url_for, abort
from authlib.integrations.flask_client import OAuth
import json
from urllib.parse import quote_plus, urlencode

app = Flask(__name__)
app.secret_key = 'umastringmuitolongaparaseroflakssecret'

appConf = {
    'OAUTH2_CLIENT_ID': 'test_web_app',
    'OAUTH2_CLIENT_SECRET': 'rbZalq1TvOgyLBrq4fR41wYEZmerEn8Q',
    "OAUTH2_ISSUER": "http://localhost:8080/realms/myorg",
    "FLASK_SECRET": "umastringmuitolongaparaseroflakssecret",
    "OAUTH2_REDIRECT_URI": 'http://localhost:5000/callback',
    "FLASK_PORT": 5000
}

app.secret_key = appConf.get("FLASK_SECRET")

oauth = OAuth(app)

oauth = OAuth(app)
oauth.register(
    "myApp2",
    # client_id vai receber "test_web_app"
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    # client_secret vai receber "rbZalq1TvOgyLBrq4fR41wYEZmerEn8Q"
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    # client_kwargs vai receber um dicionario do escopo da autenticação
    client_kwargs={
        "scope": "openid profile email"
    },
    # server_metadata_url vai receber a URL do provedor que fornece metadados do servidor, como a configuração do OAuth2 e informações sobre os tokens.
    server_metadata_url=f'{appConf.get(
        "OAUTH2_ISSUER")}/.well-known/openid-configuration'
)


@app.route('/')
def home2():
    user_info = session.get('user')
    if not user_info:
        return redirect(url_for('login'))
    return render_template('home2.html', user_info=user_info, pretty= "TOKEN JWT: "+ session.get("user")["access_token"])


@app.route('/login')
def login():
    if "user" in session:
        abort(404)
    return oauth.myApp2.authorize_redirect(redirect_uri=url_for("callback", _external=True))


@app.route('/callback')
def callback():
    token = oauth.myApp2.authorize_access_token()
    session["user"] = token
    return redirect(url_for("home2"))


@app.route("/logout")
def logout():
    id_token = session["user"]["id_token"]
    session.clear()
    logout_params = {
        "post_logout_redirect_uri": url_for("loggedOut", _external=True),
        "id_token_hint": id_token
    }

    logout_url = appConf.get("OAUTH2_ISSUER") + "/protocol/openid-connect/logout?" + \
        urlencode(logout_params, quote_via=quote_plus)

    return redirect(logout_url)


# if "user" in session: Verifica se a chave "user" está presente na sessão do usuário.
# Se estiver, significa que o usuário está autenticado e a função aborta com um erro 404.
# return redirect(url_for("home")): Se o usuário não estiver autenticado, esta linha redireciona o usuário para a página inicial ("/home")
# usando a função redirect(url_for("home")).


@app.route("/loggedout")
def loggedOut():
    if "user" in session:
        abort(404)
    return redirect(url_for("home2"))


if __name__ == '__main__':
    app.run(port=5000, debug=True)
