from flask import Flask, render_template, url_for, session, abort, redirect
from authlib.integrations.flask_client import OAuth
import json
from urllib.parse import quote_plus, urlencode

app = Flask(__name__)

# Configurações do keycloak
appConf = {
    "OAUTH2_CLIENT_ID": "test_web_app",
    "OAUTH2_CLIENT_SECRET": "rbZalq1TvOgyLBrq4fR41wYEZmerEn8Q",
    "OAUTH2_ISSUER": "http://localhost:8080/realms/myorg",
    # Flask secret serve para encriptar as senhas dos usuarios
    "FLASK_SECRET": "umastringmuitolongaparaseroflakssecret",
    # Porta que vai ser usada, deve ser diferente do keycloak
    "FLASK_PORT": 3000
}

app.secret_key = appConf.get("FLASK_SECRET")

# Associa o app Flask, fazendo com que registre os provedores OAuth
oauth = OAuth(app)
# Efetivamente registra um provedor
oauth.register(
    # Nome do provedor
    "myApp",
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


# renderiza o template "home.html" e o retorna como resposta para a requisição feita pelo usuário.
# O template é renderizado com dois argumentos:
# session=session.get("user"): Passa o valor armazenado na sessão do usuário com a chave "user" para o template,
# permitindo que o template acesse informações sobre o usuário.
# pretty=json.dumps(session.get("user"), indent=4): Converte o valor armazenado na sessão do usuário em uma string JSON formatada com indentação de 4 espaços.
# Esta variável será usada no template para exibir informações sobre o usuário de forma legível.


@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent=4))


# if "user" in session:: Verifica se a chave "user" está presente na sessão do usuário. Se estiver,
# significa que o usuário já está autenticado e a função aborta com um erro 404.

# Se o usuário não estiver autenticado, redireciona o usuário para a página de autorização do provedor OAuth (oauth.myApp.authorize_redirect).
# O argumento redirect_uri especifica para onde o provedor OAuth deve redirecionar o usuário após a autenticação.
# Neste caso, a função url_for("callback", _external=True) é usada para gerar a URL absoluta da rota "/callback",
# que é onde o provedor OAuth redirecionará o usuário após a autenticação.


@app.route("/login")
def login():
    if "user" in session:
        abort(404)
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("callback", _external=True))

# token = oauth.myApp.authorize_access_token(): Obtém o token de acesso do usuário autenticado.
# O método authorize_access_token faz uma solicitação ao provedor OAuth para trocar o código de autorização recebido pela autenticação pelo token de acesso.
# session["user"] = token: O token de acesso é armazenado na sessão do usuário com a chave "user".
# Isso permite que você mantenha o usuário autenticado em sessões futuras.
# return redirect(url_for("home")): Após armazenar o token de acesso, o usuário é redirecionado para a página inicial usando a função redirect(url_for("home")).
# A página inicial pode usar as informações contidas no token de acesso na sessão do usuário para personalizar a experiência do usuário.


@app.route("/callback")
def callback():
    token = oauth.myApp.authorize_access_token()
    session["user"] = token
    return redirect(url_for("home"))

# Obtém o token de identificação (id_token) do usuário a partir da sessão. Este token é usado para informar ao provedor OAuth qual token está sendo revogado durante o logout.
# session.clear(): Limpa todos os dados da sessão do usuário, efetivamente encerrando a sessão.
# logout_params = {...}: Define os parâmetros necessários para a solicitação de logout ao provedor OAuth.
# O parâmetro "post_logout_redirect_uri" especifica para onde o provedor deve redirecionar o usuário após o logout.
# O parâmetro "id_token_hint" fornece o token de identificação do usuário para identificar qual sessão está sendo encerrada.
# Monta a URL de logout com os parâmetros necessários e o endpoint do provedor OAuth.
# Redireciona o usuário para a URL de logout, iniciando assim o processo de logout junto ao provedor OAuth.


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
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
