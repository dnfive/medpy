from selectors import EpollSelector
from db import *
from flask import Flask, request
from flask import render_template

app = Flask(__name__)
@app.route("/", methods=['post', 'get'])
def index():
    message = ''
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        account = GetAccountInfo(login)
        print('[DEBUG] AccountInfo - ', account)
        if len(account) == 0:
            message = 'Аккаунта с таким логином не существует!'
        else:
            password_2 = account[0][2]
            if password == password_2:
                message = 'Вы успешно авторизовались!'
            else:
                message = "Неверный пароль!"
    return render_template("signin.html", message=message)

@app.route("/signup", methods=['post', 'get'])
def signup():
    message = ''
    success = ''
    if request.method == 'POST':
        first_name = request.form.get("firstname")
        username = request.form.get('username')  # запрос к данным формы
        password = request.form.get('firstpassword')
        password_2 = request.form.get('secondpassword')
        if password != password_2:
            message = "Пароли не совпадают"
        else:
            account = GetAccountInfo(username)
            if len(account) != 0:
                message = "Аккаунт с таким логином уже существует!"
            else:
                AccountInfo = {'name': first_name,
                                'login': username,
                                'password': password}
                CreateAccount(AccountInfo)
                message = 'Аккаунт успещно создан!'
                success = 'Yes'

    print(message)
    return render_template("signup.html", message=message, success=success)

if __name__ == "__main__":
    app.run(debug=True)