from flask import request, render_template, redirect, session, flash
import logging

logging.basicConfig(level=logging.INFO)

def init_app(app,red, mode) :
    app.add_url_rule('/',  view_func=saas_home, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi',  view_func=saas_home, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/saas4ssi',  view_func=saas_home, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/saas4ssi/ebsi/verifier',  view_func=saas_ebsi_verifier, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/saas4ssi/ebsi/issuer',  view_func=saas_ebsi_issuer, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/saas4ssi/menu',  view_func=saas_menu, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/saas4ssi/offers',  view_func=saas_home, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/saas4ssi/admin',  view_func=admin, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/ebsi/saas4ssi/logout',  view_func=saas_logout, methods = ['GET', 'POST'])
    return


def saas_home():
    return render_template("home.html")


def saas_menu ():
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    return render_template("menu.html")


def saas_logout():
    session.clear()
    return redirect ("/ebsi/saas4ssi")


def admin(mode) :
    if request.form['secret'] == mode.admin :
        session['is_connected'] = True
        return render_template("menu.html")
    else :
        flash("Wrong password !", "error")
        return redirect ("/ebsi/saas4ssi")


def saas_ebsi_verifier() :
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    return redirect ('/ebsi/verifier/console/select')


def saas_ebsi_issuer() :
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    return redirect ('/ebsi/issuer/console/select')
