from db import *
from flask import Flask, request, session, redirect, url_for
from flask import render_template
from datetime import datetime, date, time

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
                if account[0][4] == 1: # Если обычный пользователь
                    return redirect(url_for('mainwindow'))
                else:
                    return redirect(url_for("nav"))
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

@app.route("/nav")
def nav():
    return render_template("nav.html")

@app.route("/create", methods=['post', 'get'])
def create():
    global medcard_id
    medcard_id = int(GetMedID()[0][1])
    message = ''
    if request.method == "POST":
        first_name = request.form.get("first_name")
        second_name = request.form.get('second_name')
        third_name = request.form.get('third_name')
        ID_user = request.form.get('id_user')
        birthdate = request.form.get('birthdate')
        if len(second_name) == 0:
            message = 'Введите фамилию пациента!'
        elif len(first_name) == 0:
            message = 'Введите имя пациента!'
        elif len(third_name) == 0:
            message = 'Введите отчество пациента!'
        elif len(birthdate) == 0:
            message = 'Введите дату рождения пациента!'
        elif len(ID_user) == 0:
            message = 'Введите ID пациента!'
        elif len(GetAccountInfo(ID_user)) == 0:
            message = "Пользователь с таким ID не найден"

        cdate = datetime.now()
        cdate = cdate.strftime("%d. %m %Y")
        print(cdate)
        CardInfo = {
            'created_date': cdate,
            'first_name': first_name,
            'second_name': second_name,
            'third_name': third_name,
            'birthdate': birthdate,
            'history': "Пусто"
        }
        account = GetAccountInfo(None, ID_user)
        print(account)
        UpdateAccountInfo(account[0][3], medcard_id)
        print("Медкарта добавлена пользователю - " + str(account[0][3]) + ". ID медкарты - " + str(medcard_id))
        CreateMedCard(CardInfo)
        message = "Медкарта успешно создана!"
        return render_template("create.html", message=message,
                                            first_name=first_name,
                                            second_name=second_name,
                                            third_name=third_name,
                                            birthdate=birthdate,
                                            id_user=ID_user)
    return render_template("create.html", message=message)

@app.route("/search", methods=['post', 'get'])
def search():
    message = ""
    history = ""
    first_name = ""
    second_name = ""
    third_name = ""
    if request.method == "POST":
        first_name = request.form.get("first_name")
        second_name = request.form.get("second_name")
        third_name = request.form.get("third_name")
        if len(second_name) == 0:
            message = 'Введите фамилию пациента!'
            return render_template("search.html", message=message, history=history)
        elif len(first_name) == 0:
            message = 'Введите имя пациента!'
            return render_template("search.html", message=message, history=history)
        elif len(third_name) == 0:
            message = 'Введите отчество пациента!'
            return render_template("search.html", message=message, history=history)
        
        CardInfo = GetCardInfo(None, str(first_name), str(second_name), str(third_name))
        print(CardInfo)
        if CardInfo == False:
            message = 'Медкарта не найдена!'    
        else:
            history = str(CardInfo['history'])
    
    return render_template("search.html", message=message, 
                                            history=history,
                                            first_name=first_name,
                                            second_name=second_name,
                                            third_name=third_name)

@app.route("/edit", methods=['post', 'get'])
def edit():
    message = ""
    if request.method == "POST":
        first_name = request.form.get("first_name")
        second_name = request.form.get("second_name")
        third_name = request.form.get("third_name")
        history = request.form.get("history")
        if len(second_name) == 0:
            message = 'Введите фамилию пациента!'
            return render_template("edit.html", message=message)
        elif len(first_name) == 0:
            message = 'Введите имя пациента!'
            return render_template("edit.html", message=message)
        elif len(third_name) == 0:
            message = 'Введите отчество пациента!'
            return render_template("edit.html", message=message)
        elif len(history) == 0:
            message = "Введена пустая запись!"            
            return render_template("edit.html", message=message)
        
        CardInfo = GetCardInfo(None, str(first_name), str(second_name), str(third_name))
        print("[DEBUG] " + str(CardInfo))
        if CardInfo == False:
            message = 'Медкарта не найдена!'
        else:
            CardInfo['history'] += ".\n" + str(datetime.now().strftime("%d. %m %Y")) + " .\n " + str(history)
            history = datetime.now().strftime("%d. %m %Y") + ". \n" + history
            UpdateHistoryMed(CardInfo['ID'], CardInfo['history'], history)

        return render_template("edit.html", message=message,
                                        first_name=first_name,
                                        second_name=second_name,
                                        third_name=third_name,
                                        history=history)
    return render_template("edit.html", message=message)
if __name__ == "__main__":
    app.run(debug=True)