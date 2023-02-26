import os
import time
from flask import Flask
from flask_session import Session
from datetime import timedelta
from flask_qrcode import QRcode
import redis
import logging
import environment

logging.basicConfig(level=logging.INFO)

# Environment variables set in gunicornconf.py  and transfered to environment.py
mode = environment.currentMode()

# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Centralized  routes : modules in ./routes
from routes import saas4ssi
from routes import api_verifier_ebsi, ebsi_verifier_console
from routes import api_issuer_ebsi, ebsi_issuer_console

# Server Release
VERSION = "0.1.0"
texte ="""

To start this application open """ + mode.server + """ in your browser.\nPassword is "admin".
Then choose to generate an issuer or a verifier.

"""
logging.info(texte)

# Framework Flask and Session setup
app = Flask(__name__)
app.jinja_env.globals['Version'] = VERSION
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=360) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "123456789"


sess = Session()
sess.init_app(app)
qrcode = QRcode(app)


# Init routes
ebsi_verifier_console.init_app(app, red, mode)
api_verifier_ebsi.init_app(app, red, mode)
ebsi_issuer_console.init_app(app, red, mode)
api_issuer_ebsi.init_app(app, red, mode)
saas4ssi.init_app(app, red, mode)


# MAIN entry point for test
if __name__ == '__main__':
    app.run(host = mode.flaskserver, port= mode.port, debug = mode.test, threaded=True)