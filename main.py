from flask import Flask, render_template, url_for, request, redirect, flash, get_flashed_messages, session
from dbController import *
import random
import hashlib
from random import choice, randint
import string
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'jagjigfiljgfjioagojgraijogaoinjdhaihefiefh'
# db = SQLAlchemy(app)

# class Article(db.Model):

def WhatNav():
    if session.get("auth"):
        arr = [{"url":"/", "name": "Главная"},{"url":"/user", "name": session.get("login")}, {"url":"/logout", "name": "exit"}]
    else:
        arr = [{"url": "/", "name": "Главная"}, {"url": "/reg", "name": "Регистрация / Авторизация"}]
    return arr

def WhatTypes(arr):

    if session.get("auth"):
        types = []
        for i in arr:

            types.append({"id_type": i[0], "type": i[1]})
    else:

        types = [{"id_type": 1, "type": "Публичная"}]

    return types

#заполнение типов если пусто
if not getTypes():
    types = ["Публичная", "Общего доступа", "Приватная"]
    setTypes(types)



@app.route('/')
def index():
    if session.get("auth") == None:
        session["auth"] = False
    arr = getTypes()
    print("index")
    return render_template('index.html', nav=WhatNav(), types=WhatTypes(arr))

@app.route('/auth')
def auth():
    return render_template('auth.html', nav = WhatNav())

@app.route('/noasses')
def noasses():
    return render_template('noasses.html', nav = WhatNav())

@app.route('/user')
def user():
    arr = getTypes()

    links = getLinksByUser(session.get("user_id"))
    return render_template('user.html', nav = WhatNav(), links = links, types = WhatTypes(arr))


@app.route('/logout')
def logout():
    session.pop('login', None)
    session.pop('auth', None)
    session.pop('link', None)
    return redirect('/', code = 302)

@app.route('/reg')
def reg():
    return render_template('reg.html', nav = WhatNav())

@app.route('/del', methods=['POST'])
def delete():
    print("delete")
    print(request.form['id'])
    if request.method == 'POST':
        link_id = request.form['id']
        deleteLink(link_id)
        return redirect('/user', code=302)


@app.route('/edit_psev', methods=['POST'])
def edit_psev():
    print("edit_psev")

    if request.method == 'POST':
        link_id = request.form['id']
        psev = request.form["psev"]
        new_link = request.host_url + "meow/" + psev
        if getPsev(new_link) != None:
            flash("псевдоним занят", category="errors")
        else:
            editPsevOfLink(new_link, link_id)
        return redirect('/user', code=302)

@app.route('/edit_type', methods=['POST'])
def edit_type():
    print("edit_type")

    if request.method == 'POST':
        link_id = request.form['id']
        type_id = request.form["type"]
        editTypeOfLink(type_id,link_id)
        return redirect('/user', code=302)


@app.route('/insert', methods=['POST'])
def insert():
    print("ddddd")
    if request.method == 'POST':

        login = request.form['login']
        cpassw = request.form['cpass']
        passw = request.form['pass']




        if (login != '' and cpassw != '' and passw != ''):
            if(getLogin(login) == None):
                if cpassw == passw:
                    hashas = hashlib.md5(request.form["pass"].encode())
                    password = hashas.hexdigest()
                    insertUser(login,password)
                    id_user = getLogin(login)
                    session["user_id"] = id_user[0]
                    session["login"] = login
                    session["auth"] = True

                    return redirect('/', code = 302)
                else:

                    flash("Пароли не совподают")
                    return redirect('/reg', code = 302)
            else:
                flash("Логин уже занят")
                return redirect('/reg', code=302)
        else:
            flash("Заполните все поля")
            return redirect('/reg', code=302)



@app.route('/memberlogin', methods=['POST'])
def memberlogin():
    print("aaaa")

    print(session.get("link"))
    if request.method == 'POST':

        login = request.form['login']
        passw = request.form['pass']
        print(getLogin(login))
        if(getLogin(login) != None):
            print(login)
            print(passw)
            hashas = hashlib.md5(request.form["pass"].encode())
            password = hashas.hexdigest()
            passwUser = getPass(login, password)



            if passwUser != None and passwUser[0] == password:
                session["login"] = login
                session["auth"] = True
                id_user = getLogin(login)
                session["user_id"] = id_user[0]
                if(session.get("link") != None):
                    return redirect(session.get("link"))
                else:
                    return redirect('/', code = 302)
            else:
                flash("Пароль не тот")
                return redirect('/auth', code = 302)
        else:
            flash("Логин не найден")
            return redirect('/auth', code = 302)



@app.route('/create_link', methods=['POST'])
def createlink():
    if request.method == 'POST':
        host_url = request.host_url

        print(host_url)
        link = request.form['link']
        type = request.form['type']
        print(session.get("auth"))
        print(link)
        if link != "":
            if request.form.getlist('ispsev') :
                psev = request.form['psev']
                if psev != '':
                    link_psev =  host_url + "meow/" + psev
                    print(link_psev)
                    print(getPsev(psev))
                    if getPsev(link_psev) != None:
                        print(getPsev(psev))
                        flash("Выберите другой псевдоним, этот занят", category="errors")
                    else:
                        short_link = host_url + "meow/" + psev
                        print("lin")
                        if session.get("auth"):
                            print("linklinkddddddddddddd")
                            insertLink(link, session.get("user_id"), type, short_link)
                        else:
                            insertLinkNotAuth(link, type, short_link)
                            print("linklinkddddddddddddd")
                        flash(link, category="link")
                        flash(short_link, category="url")
                else:
                    flash("Введите псевдоним", category="errors")
            else:
                short_link = host_url + "meow/"  + ''.join(choice(string.ascii_letters+string.digits) for _ in range(randint(8, 12)))
                if session.get("auth"):
                    insertLink(link, session.get("user_id"),type,short_link);

                else:
                    insertLinkNotAuth(link, type, short_link)
                flash(link, category="link")
                flash(short_link, category="url")

        else:
            flash("Введите ссылку", category="errors")
    return redirect("/", code=302)

@app.route('/meow/<short_link>')
def redirect_link(short_link):
    print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    user_link = request.host_url + "meow/" + short_link
    link_user = getPsev(user_link)
    print(short_link)
    print(user_link)

    link = link_user[0]
    print(link)
    if link != None:

        print(getTypebyLink(user_link))
        type = getTypebyLink(user_link)
        type_link = type[0]
        print("ggggggggggggggggg")

        if type_link == 1:
            print("ggggggggggggggggg")
            updateCounOfLink(user_link)
            return redirect(link)
        else:
            session["link"] = user_link
            if session.get("auth"):
                if type_link == 2:
                    updateCounOfLink(user_link)
                    session.pop('link', None)
                    return redirect(link)
                elif type_link == 3:
                    if session.get("user_id") == getUserbyLink(user_link)[0]:
                        updateCounOfLink(user_link)
                        session.pop('link', None)
                        return redirect(link)
                    else:
                        session.pop('link', None)
                        return redirect("/noasses")
            else:
                return redirect("/auth")








if __name__ == '__main__':
    app.run(debug=True)