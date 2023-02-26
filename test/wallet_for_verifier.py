import requests
import json
from urllib.parse import parse_qs, urlparse
from jwcrypto import jwk, jwt
from datetime import datetime
import uuid
import sys
sys.path.append('../')

import ebsi

import logging
logging.basicConfig(level=logging.INFO)

# wallet keys
# KEY_DICT = ebsi.generate_key('P-256')
KEY_DICT = {
  "kty" : "EC",
  "d" : "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
  "use" : "sig",
  "crv" : "P-256",
  "x" : "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
  "y" : "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  "alg" : "ES256",
}


# Credential received from issuer as a jwt_vc
credential = 'eyJraWQiOiJkaWQ6ZWJzaTp6bXBybUZNb1VxNUR1Yjhvd0tjam9tWiNkZDJhYWU4NzRjMGQ0ZmEwODU3NDkxNzAzYTJkYzdhYSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2In0.eyJzdWIiOiJkaWQ6ZWJzaTp6bnhudHhRck4zNjlHc055akZqWWI4ZnV2VTdnM3NKR3lZR3dNVGNVR2R6dXkiLCJuYmYiOjE2Nzc0MTY1OTUsImlzcyI6ImRpZDplYnNpOnptcHJtRk1vVXE1RHViOG93S2Nqb21aIiwiaWF0IjoxNjc3NDE2NTk1LCJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUF0dGVzdGF0aW9uIiwiVmVyaWZpYWJsZURpcGxvbWEiXSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJ1cm46dXVpZDo1NzYxMTIxZC00YzQ1LTQyZDAtYmRkMi1mMThjMDI2YmVlZTYiLCJpc3N1ZXIiOiJkaWQ6ZWJzaTp6bXBybUZNb1VxNUR1Yjhvd0tjam9tWiIsImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDItMjZUMTM6MDM6MTVaIiwiaXNzdWVkIjoiMjAyMy0wMi0yNlQxMzowMzoxNVoiLCJ2YWxpZEZyb20iOiIyMDIzLTAyLTI2VDEzOjAzOjE1WiIsImV4cGlyYXRpb25EYXRlIjoiMjAyMi0wOC0zMVQwMDowMDowMFoiLCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9hcGkucHJlcHJvZC5lYnNpLmV1L3RydXN0ZWQtc2NoZW1hcy1yZWdpc3RyeS92MS9zY2hlbWFzLzB4YmY3OGZjMDhhN2E5ZjI4ZjU0NzlmNThkZWEyNjlkMzY1N2Y1NGYxM2NhMzdkMzgwY2Q0ZTkyMjM3ZmI2OTFkZCIsInR5cGUiOiJKc29uU2NoZW1hVmFsaWRhdG9yMjAxOCJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDplYnNpOnpueG50eFFyTjM2OUdzTnlqRmpZYjhmdXZVN2czc0pHeVlHd01UY1VHZHp1eSIsImF3YXJkaW5nT3Bwb3J0dW5pdHkiOnsiaWQiOiJodHRwczovL3d3d2VuLnVuaS5sdS9mZGVmL3N0dWRpZXMvc2Nob2xhcnNoaXBzIiwibG9jYXRpb24iOiJMVVhFTUJPVVJHIn0sImRhdGVPZkJpcnRoIjoiMjAwMS0wMy0yMSIsImZhbWlseU5hbWUiOiJET0UiLCJnaXZlbk5hbWVzIjoiSm9obiIsImdyYWRpbmdTY2hlbWUiOnsiaWQiOiJodHRwczovL3d3d2VuLnVuaS5sdS9zdHVkaWVzL2VjdHNfY3JlZGl0cyIsInRpdGxlIjoiRUNUUyBjcmVkaXRzIn0sImlkZW50aWZpZXIiOiIwOTA0MDA4MDg0SCIsImxlYXJuaW5nQWNoaWV2ZW1lbnQiOnsiZGVzY3JpcHRpb24iOiJUaGUgTWFzdGVyIGluIEluZm9ybWF0aW9uIGFuZCBDb21wdXRlciBTY2llbmNlcyAoTUlDUykgYXQgdGhlIFVuaXZlcnNpdHkgb2YgTHV4ZW1ib3VyZyBlbmFibGVzIHN0dWRlbnRzIHRvIGFjcXVpcmUgZGVlcGVyIGtub3dsZWRnZSBpbiBjb21wdXRlciBzY2llbmNlIGJ5IHVuZGVyc3RhbmRpbmcgaXRzIGFic3RyYWN0IGFuZCBpbnRlcmRpc2NpcGxpbmFyeSBmb3VuZGF0aW9ucywgZm9jdXNpbmcgb24gcHJvYmxlbSBzb2x2aW5nIGFuZCBkZXZlbG9waW5nIGxpZmVsb25nIGxlYXJuaW5nIHNraWxscy4iLCJpZCI6Imh0dHBzOi8vd3d3ZnIudW5pLmx1L2Zvcm1hdGlvbnMvZnN0bS9tYXN0ZXJfaW5faW5mb3JtYXRpb25fYW5kX2NvbXB1dGVyX3NjaWVuY2VzIiwidGl0bGUiOiJNYXN0ZXIgaW4gSW5mb3JtYXRpb24gYW5kIENvbXB1dGVyIFNjaWVuY2VzIn0sImxlYXJuaW5nU3BlY2lmaWNhdGlvbiI6eyJlY3RzQ3JlZGl0UG9pbnRzIjoiMTIwIiwiaWQiOiJodHRwczovL3d3d2ZyLnVuaS5sdS9mb3JtYXRpb25zL2ZzdG0vbWFzdGVyX2luX2luZm9ybWF0aW9uX2FuZF9jb21wdXRlcl9zY2llbmNlcyJ9fSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6Imh0dHBzOi8vZXNzaWYuZXVyb3BhLmV1L3N0YXR1cy9lZHVjYXRpb24jaGlnaGVyRWR1Y2F0aW9uIzM5MmFjN2Y2LTM5OWEtNDM3Yi1hMjY4LTQ2OTFlYWQ4ZjE3NiIsInR5cGUiOiJDcmVkZW50aWFsU3RhdHVzTGlzdDIwMjAifSwiZXZpZGVuY2UiOnsiZG9jdW1lbnRQcmVzZW5jZSI6WyJQaHlzaWNhbCJdLCJldmlkZW5jZURvY3VtZW50IjpbIlBhc3Nwb3J0Il0sImlkIjoiaHR0cHM6Ly9lc3NpZi5ldXJvcGEuZXUvdHNyLXZhL2V2aWRlbmNlL2YyYWVlYzk3LWZjMGQtNDJiZi04Y2E3LTA1NDgxOTJkNTY3OCIsInN1YmplY3RQcmVzZW5jZSI6IlBoeXNpY2FsIiwidHlwZSI6WyJEb2N1bWVudFZlcmlmaWNhdGlvbiJdLCJ2ZXJpZmllciI6ImRpZDplYnNpOjI5NjJmYjc4NGRmNjFiYWEyNjdjODEzMjQ5NzUzOWY4YzY3NGIzN2MxMjQ0YTdhIn19LCJqdGkiOiJ1cm46dXVpZDo1NzYxMTIxZC00YzQ1LTQyZDAtYmRkMi1mMThjMDI2YmVlZTYifQ.aQmBRiWEsiC-BuUxU5Ar0t76j727tp0Aa0tPsFXISFJtdkJJaC1K2qUJJWkP8PI_8M-rsm3Rt35NPMMp1-NfoA'


# SIOPV2 qrcode provided by verifier
qrcode = " openid://?scope=openid&response_type=id_token&client_id=did%3Aebsi%3AzZWTnbEeCHAngw2u3bw4xnR&redirect_uri=http%3A%2F%2F10.39.17.153%3A3000%2Febsi%2Flogin%2Fendpoint%2F69ddaa60-b5d6-11ed-b135-dbe81cf4595b&nonce=69ddaa61-b5d6-11ed-b135-dbe81cf4595b&request_uri=http%3A%2F%2F10.39.17.153%3A3000%2Febsi%2Flogin%2Frequest_uri%2F69ddaa60-b5d6-11ed-b135-dbe81cf4595b&claims=%7B%27id_token%27%3A+%7B%27email%27%3A+None%7D%2C+%27vp_token%27%3A+%7B%27presentation_definition%27%3A+%7B%27id%27%3A+%2769ddaa62-b5d6-11ed-b135-dbe81cf4595b%27%2C+%27input_descriptors%27%3A+%5B%7B%27id%27%3A+%2769ddaa63-b5d6-11ed-b135-dbe81cf4595b%27%2C+%27name%27%3A+%27Input+descriptor+1%27%2C+%27purpose%27%3A+%27This+is+purpose+1%27%2C+%27constraints%27%3A+%7B%27fields%27%3A+%5B%7B%27path%27%3A+%5B%27%24.credentialSchema.id%27%5D%2C+%27filter%27%3A+%7B%27type%27%3A+%27string%27%2C+%27pattern%27%3A+%27https%3A%2F%2Fapi.preprod.ebsi.eu%2Ftrusted-schemas-registry%2Fv1%2Fschemas%2F0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd%27%7D%7D%5D%7D%7D%5D%2C+%27format%27%3A+%7B%27jwt_vp%27%3A+%7B%27alg%27%3A+%5B%27ES256K%27%2C+%27ES256%27%2C+%27PS256%27%2C+%27RS256%27%5D%7D%7D%7D%7D%7D"
qrcode = "openid://?scope=openid&response_type=id_token&client_id=did%3Aebsi%3AzZWTnbEeCHAngw2u3bw4xnR&redirect_uri=http%3A%2F%2F10.39.17.153%3A3000%2Febsi%2Flogin%2Fendpoint%2Faab4b348-b5e1-11ed-b135-dbe81cf4595b&nonce=aab4b349-b5e1-11ed-b135-dbe81cf4595b&request_uri=http%3A%2F%2F10.39.17.153%3A3000%2Febsi%2Flogin%2Frequest_uri%2Faab4b348-b5e1-11ed-b135-dbe81cf4595b&claims=%7B%27id_token%27%3A+%7B%27email%27%3A+None%7D%2C+%27vp_token%27%3A+%7B%27presentation_definition%27%3A+%7B%27id%27%3A+%27aab4b34a-b5e1-11ed-b135-dbe81cf4595b%27%2C+%27input_descriptors%27%3A+%5B%7B%27id%27%3A+%27aab4b34b-b5e1-11ed-b135-dbe81cf4595b%27%2C+%27name%27%3A+%27Input+descriptor+1%27%2C+%27purpose%27%3A+%27This+is+purpose+1%27%2C+%27constraints%27%3A+%7B%27fields%27%3A+%5B%7B%27path%27%3A+%5B%27%24.credentialSchema.id%27%5D%2C+%27filter%27%3A+%7B%27type%27%3A+%27string%27%2C+%27pattern%27%3A+%27https%3A%2F%2Fapi.preprod.ebsi.eu%2Ftrusted-schemas-registry%2Fv1%2Fschemas%2F0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd%27%7D%7D%5D%7D%7D%5D%2C+%27format%27%3A+%7B%27jwt_vp%27%3A+%7B%27alg%27%3A+%5B%27ES256K%27%2C+%27ES256%27%2C+%27PS256%27%2C+%27RS256%27%5D%7D%7D%7D%7D%7D"

parse_result = urlparse(qrcode)
result = parse_qs(parse_result.query)
redirect_uri = result['redirect_uri'][0]
client_id = result['client_id'][0]
nonce = result["nonce"][0]
claims = result["claims"][0]

logging.info('redirect uri = %s', redirect_uri)
logging.info('claims = %s', claims)
logging.info('client_id = %s', client_id)
logging.info('nonce = %s', nonce)


def build_id_token(key, audience, nonce) :
    """
    self issued ID token
    https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11
    
    """
    alg = ebsi.alg(key)
    wallet_key = jwk.JWK(**key) 
    did = ebsi.generate_np_ebsi_did(key)
    vm = ebsi.verification_method(did, key)
    header = {
        "typ" :"JWT",
        "alg": alg,
        "jwk" : ebsi.pub_key(key),
        "kid" : vm
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "aud" : audience,
        "exp": round(datetime.timestamp(datetime.now())) + 1000,
        "sub" : did,
        "iss": "https://self-issued.me/v2",
        "nonce": nonce,
        "_vp_token": {
            "presentation_submission": {
            "definition_id": "conformance_mock_vp_request",    
            "id": "VA presentation Talao",
            "descriptor_map": [
                {
                    "id": "conformance_mock_vp",
                    "format": "jwt_vp",
                    "path": "$",
                }
            ]
            }
        }
    }
    token = jwt.JWT(header=header,claims=payload, algs=[alg])
    token.make_signed_token(wallet_key)
    return token.serialize()
   

"""
Build and sign verifiable presentation as vp_token
Ascii is by default in the json string 
"""
def build_vp_token(credential, key, audience, nonce) :
    wallet_key = jwk.JWK(**key) 
    alg = ebsi.alg(key)
    did = ebsi.generate_np_ebsi_did(key)
    vm = ebsi.verification_method(did, key)
    header = {
        "typ" :"JWT",
        "alg": alg,
        "kid" : vm,
        "jwk" : ebsi.pub_key(key),
    }
    iat = round(datetime.timestamp(datetime.now()))
    payload = {
        "iat": iat,
        "jti" : "http://example.org/presentations/talao/01",
        "nbf" : iat -10,
        "aud" : audience,
        "exp": iat + 1000,
        "sub" : did,
        "iss" : did,
        "vp" : {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": str(uuid.uuid1()),
            "type": ["VerifiablePresentation"],
            "holder": ebsi.generate_np_ebsi_did(key),
            "verifiableCredential": credential
        },
        "nonce": nonce
    }
    token = jwt.JWT(header=header,claims=payload, algs=[alg])
    token.make_signed_token(wallet_key)
    return token.serialize()


"""
send response to verifier

https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-a.5.2

"""
def send_response(id_token, vp_token, redirect_uri) :
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = "id_token="+ id_token + "&vp_token=" + vp_token
    resp = requests.post(redirect_uri, headers=headers, data=data)
    return resp.json()


# main
id_token = build_id_token(KEY_DICT, client_id, nonce)
vp_token =  build_vp_token(credential, KEY_DICT, client_id, nonce)
result = send_response(id_token, vp_token, redirect_uri)
logging.info('result = %s', json.dumps(result, indent=4))

