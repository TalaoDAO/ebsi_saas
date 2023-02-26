from flask import Flask, request, jsonify
import socket
import requests
import json
from urllib.parse import parse_qs, urlparse
import uuid
import redis
import sys
sys.path.append('../')

import ebsi
import logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# Redis init red = redis.StrictRedis() for request_uri
red= redis.Redis(host='localhost', port=6379, db=0)

"""
If needed one can steup an IP tunnel for local testing wit ngrok
example : ngrok http http://192.168.0.65:4000


EBSILUX PORTAL
https://ebsilux-iss.list.lu/portal
student01 / 0123456789


https://api-pilot.ebsi.eu/trusted-issuers-registry/v3/issuers/did:ebsi:zeFCExU2XAAshYkPCpjuahA#3623b877bbb24b08ba390f3585418f53
https://api-pilot.ebsi.eu/trusted-issuers-registry/v3/issuers/did:ebsi:zeFCExU2XAAshYkPCpjuahA#3623b877bbb24b08ba390f3585418f53/attributes


Only one credential is issued 

Deffered credential not supported

"""

ngrok =  "https://7fa5-77-140-52-235.ngrok.io" # for callbacl oh the wallet
ngrok = "http://10.39.21.243:4000"

# wallet key
#KEY_DICT = ebsi.generate_key('P-256')
KEY_DICT = {
  "kty" : "EC",
  "d" : "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
  "use" : "sig",
  "crv" : "P-256",
  "x" : "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
  "y" : "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  "alg" : "ES256",
}
DID = ebsi.generate_np_ebsi_did(KEY_DICT)


logging.info('wallet private key = %s', KEY_DICT)
logging.info('wallet DID = %s', DID)


# qrcode displayed by issuer
qrcode = "openid://initiate_issuance?issuer=http%3A%2F%2F10.39.21.243%3A3000%2Febsi%2Fissuer%2Fgrrsydiuou&credential_type=https%3A%2F%2Fapi.preprod.ebsi.eu%2Ftrusted-schemas-registry%2Fv1%2Fschemas%2F0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd&op_state=test_authorization_server"

parse_result = urlparse(qrcode)
result = parse_qs(parse_result.query)
issuer = result['issuer'][0]
credential_type = result["credential_type"][0]
op_state = result["op_state"][0]
pre_authorized_code = result.get('pre-authorized_code', [{}])[0]

logging.info('issuer = %s', issuer)
logging.info('credential type = %s', credential_type)
logging.info('openid configuration = %s', issuer + '/.well-known/openid-configuration')
logging.info('pre_authorized_code = %s', pre_authorized_code)

try :
    url = issuer + '/.well-known/openid-configuration'
    r = requests.get(url) 
except :
    logging.error('issuer access closed')
    sys.exit()

logging.info('issuer status code = %s', r.status_code)

credential_issuer = r.json()
authorization_endpoint = credential_issuer['authorization_endpoint']
token_endpoint = credential_issuer['token_endpoint']
credential_endpoint = credential_issuer['credential_endpoint']

logging.info('authorization enpoint = %s', authorization_endpoint)
logging.info('token endpoint = %s', token_endpoint)
logging.info('credential endpoint = %s', credential_endpoint)


def authorization_request(did, ngrok, credential_type, red ) :
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Basic Altme' # not used by issuer
    }
    state = str(uuid.uuid1())
    my_request = {
        "scope" : "openid",
        "client_id" : did,
        "response_type" : "code",
        "authorization_details" :json.dumps([{ 
                "type":"openid_credential",
                "credential_type": credential_type,
                "format":"jwt_vc"
        }]),
        "redirect_uri" :  ngrok + "/callback",
        "state" : state,
        "op_state" : op_state,
        "request_uri" : ngrok + "/request_uri/" + state
    }
    red.setex(state, 100, json.dumps(my_request))
    logging.info("request = %s", my_request)
    resp = requests.get(authorization_endpoint, headers=headers, params = my_request)
    logging.info('response status code authorization request = %s', resp.status_code)
    try :
        return resp.json()
    except : 
        return (resp.content)


def token_request(code, ngrok ) :
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    if pre_authorized_code :
        data = { 
            "pre-authorized_code" : code,
            "grant_type" : 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    }
    else :   
        data = { 
            "code" : code,
            "grant_type" : "authorization_code",
            "redirect_uri" :  ngrok + "/callback"
    }
    logging.info("token request data = %s", data)
    resp = requests.post(token_endpoint, headers=headers, data = data)
    logging.info("status code token endpoint = %s", resp.status_code)
    return resp.json()


def credential_request(access_token, proof ) :
    # https://api-conformance.ebsi.eu/docs/specs/credential-issuance-guidelines#credential-request
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token 
        }
    data = { 
        "type" : credential_type,
        "format" : "jwt_vc",
        "proof" : {
            "proof_type": "jwt",
            "jwt": proof
        }
    }
    resp = requests.post(credential_endpoint, headers=headers, data = json.dumps(data))
    logging.info('status code credential endpoint = %s', resp.status_code)
    return resp.json()



# authorization request only needed if authorization_code flow
@app.route('/start' , methods=['GET', 'POST'], defaults={'red' :red})
def start(red) :
    return authorization_request(DID, ngrok, credential_type, red)


# callback endpoint only needed if authorization_code flow
@app.route('/callback' , methods=['GET', 'POST']) 
def callback() :
    logging.info('callback request header = %s' , request.headers)
    if request.args.get('error') :
        return jsonify(request.args)

    # code received from authorization server
    code = request.args["code"]
    logging.info('code received = %s', code)
    
    # access token request
    result = token_request(code, ngrok )
    if result.get('error') :
        return jsonify(result)

    # access token received
    access_token = result["access_token"]
    c_nonce = result["c_nonce"]
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = ebsi.build_proof_of_key_ownership(KEY_DICT, "aud", c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result = credential_request(access_token, proof )
    if result.get('error') :
        return jsonify(result)
    
    # credential received
    logging.info("credential received = %s", result)   

    # Check credential signature with public key received from EBSI
    header = ebsi.get_header_from_token(result['credential'])
    issuer_vm = header['kid']
    issuer_did = issuer_vm.split('#')[0]
    logging.info('issuer did = %s', issuer_did)
    logging.info('issuer kid = %s', issuer_vm)
    pub_key = ebsi.get_lp_public_jwk(issuer_did,issuer_vm)
    if not pub_key :
        logging.warning('Issuer not registered')
        return jsonify('Issuer not registered in EBSI registry')

    logging.info('EBSI issuer pub key = %s', pub_key)
    try : 
        ebsi.verify_jwt_credential(result['credential'], pub_key)
        logging.info('signature check success')
        return jsonify('OK well done !')
    except :
        logging.warning('signature check failed')
        return jsonify('Credential signature check failed !')
    

# local http server init
def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP

# If pre authorized code, the script starts here. If not the wallet starts the local server
if pre_authorized_code :
    # access token request
    code = pre_authorized_code
    logging.info('This is a pre_authorized-code flow')
    result = token_request(code, ngrok )
    logging.info('token endpoint response = %s', result)
    if result.get('error') :
        logging.warning('token endpoint error return code = %s', result)
        sys.exit()

    # access token received
    access_token = result["access_token"]
    c_nonce = result["c_nonce"]
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = ebsi.build_proof_of_key_ownership(KEY_DICT, "aud", c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result = credential_request(access_token, proof )
    if result.get('error') :
        logging.warning('credential enpoint error return code = %s', result)
    
    # credential received
    logging.info("'credential endpoint response = %s", result)  
    
    # Check credential signature with public key received from EBSI
    header = ebsi.get_header_from_token(result['credential'])
    issuer_vm = header['kid']
    issuer_did = issuer_vm.split('#')[0]
    logging.info('issuer did = %s', issuer_did)
    logging.info('issuer kid = %s', issuer_vm)
    pub_key = ebsi.get_lp_public_jwk(issuer_did,issuer_vm)
    if not pub_key :
        logging.warning('Issuer not registered')
        sys.exit()

    logging.info('EBSI issuer pub key = %s', pub_key)
    try : 
        ebsi.verify_jwt_credential(result['credential'], pub_key)
        logging.info('signature check success')
    except :
        logging.warning('signature check failed')
    sys.exit()

# MAIN entry point. Flask http server
if __name__ == '__main__':
    # to get the local server IP 
    IP = extract_ip()
    # server start
    app.run(host = IP, port= 4000, debug=True)