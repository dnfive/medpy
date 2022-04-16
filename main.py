from fcntl import F_SEAL_SEAL
from db import *
from flask import Flask, request, session, redirect, url_for
from flask import render_template

app = Flask(__name__)

app.secret_key = 'BAD_SECRET_KEY'

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
            password_2 = str(account[0][2])
            password = GetHashString(password)
            if password == password_2:
                message = 'Вы успешно авторизовались!'
                session['user'] = {
                    'ID': int(account[0][3]),
                    'name': str(account[0][0]),
                    'login': str(account[0][1]),
                    'password': str(account[0][2]),
                    'type': int(account[0][4]),
                    'medid': int(account[0][5])
                }
                return redirect(url_for('mainwindow'))
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
                                'password': password,
                                'type': 0}
                CreateAccount(AccountInfo)
                message = 'Аккаунт успещно создан!'
                success = 'Yes'

    print(message)
    return render_template("signup.html", message=message, success=success)

@app.route("/main")
def mainwindow():
    CardInfo = GetCardInfo(session['user']['medid'])
    if CardInfo == False:
        have_card = ""
        message = ""
        return render_template("main.html", message = message, 
                                        have_card=have_card)
    else:
        first_name = CardInfo['first_name']
        second_name = CardInfo['second_name']
        third_name = CardInfo['third_name']
        birthdate = CardInfo['birthdate']
        medid = CardInfo['ID']
        history = CardInfo['history']
        have_card = "Yes"
        message = ""
        return render_template("main.html", message = message, 
                                        have_card=have_card,
                                        first_name=first_name,
                                        second_name=second_name,
                                        third_name=third_name,
                                        birthdate=birthdate,
                                        medid=medid,
                                        history=history)

if __name__ == "__main__":
    app.run(debug=True)