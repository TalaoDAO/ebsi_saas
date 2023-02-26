

import json
import requests
from flask import Flask, render_template, request, redirect, jsonify, session
from flask_session import Session
import logging
import environment

logging.basicConfig(level=logging.INFO)

# Environment variables set in gunicornconf.py  and transfered to environment.py
mode = environment.currentMode()

# Framework Flask and Session setup
app = Flask(__name__)
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['SECRET_KEY'] = "OCML3BRawWEUeaxcuKHLpw" + mode.password

sess = Session()
sess.init_app(app)

client_id = "natfwldlls"
client_secret = "cb93e6f0-a926-11ed-b4c3-a997f42ce5ac"
api_endpoint = "http://192.168.0.65:3000/ebsi/issuer/natfwldlls"

@app.route('/', methods = ['GET', 'POST'])
def home() :
        if request.method == 'GET' :
                return render_template("test/university.html")
        if request.method == 'POST' :
                # prepare the VC to be signed and sent to the wallet
                file_path = './verifiable_credentials/VerifiableDiploma.jsonld'
                vc = json.load(open(file_path))
                credential_type = "verifiableDiploma"
                pre_authorized_code = "345"
                # customer API call to get the redirect to qrcode page
                result = get_qrcode_link(api_endpoint, client_secret, pre_authorized_code, vc, credential_type)
                if not result :
                        return jsonify("Issuer not available")
                try :
                        result['error']
                        return jsonify(result)
                except :
                        # redirect to QRcode page
                       return redirect (result['qrcode_link'])


@app.route('/callback', methods = ['GET', 'POST'])
def callback() :
        return render_template('test/university_callback.html')


def get_qrcode_link(api_endpoint, client_secret, pre_authorized_code, vc, credential_type) :
        """
        Customer API call 

        curl -d '{"vc" : {"key1" : "test1"}, "pre-authorized_code" : "1234"}' -H "Content-Type: application/json" -H "Authorization: Basic cb93e6f0-a926-11ed-b4c3-a997f42ce5ac"  -X POST http://192.168.0.65:3000/ebsi/issuer/natfwldlls

        """
        headers = {
                'Content-Type': 'application/json',
                'Authorization' :'Basic ' + client_secret
        }
        data = { 
                "vc" : vc,
                "pre-authorized_code" : pre_authorized_code,
                "credential_type" : credential_type
        }
        try :
                resp = requests.post(api_endpoint, headers=headers, data = json.dumps(data))
        except :
                return
        return resp.json()



# MAIN entry point for test
if __name__ == '__main__':
        app.run(host = mode.flaskserver, port= 5000, debug = mode.test, threaded=True)