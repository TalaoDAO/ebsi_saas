
"""
EBSI lib for python issuers, varifiers  and wallets

 https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
 VC/VP https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations
 DIDS method https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
 supported signature : https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations

"""



import hashlib
from pyld import jsonld
from jwcrypto import jwk, jws, jwt
import base64
import base58
import json
from jwcrypto.common import json_encode
from datetime import datetime
import os
import requests
import logging
logging.basicConfig(level=logging.INFO)


def generate_key(curve) :
  """
  alg value https://www.rfc-editor.org/rfc/rfc7518#page-6

   +--------------+-------------------------------+--------------------+
   | "alg" Param  | Digital Signature or MAC      | Implementation     |
   | Value        | Algorithm                     | Requirements       |
   +--------------+-------------------------------+--------------------+
   | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
   |              | SHA-256                       |                    |
   | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
   |              | SHA-384                       |                    |
   | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
   |              | SHA-512                       |                    |
   | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
   | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
   | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
   +--------------+-------------------------------+--------------------+
  """
  if curve in  ['P-256', 'P-384', 'P-521', 'secp256k1'] :
    key = jwk.JWK.generate(kty='EC', crv='P-256')
  elif curve == 'RSA' :
    key = jwk.JWK.generate(kty='RSA', size=2048)
  else :
    raise Exception("Curve not supported")
  return json.loads(key.export(private_key=True))  


def alg(key) :
  key = json.loads(key) if isinstance(key, str) else key
  if key['kty'] == 'EC' :
    if key['crv'] in ['secp256k1', 'P-256K'] :
      key['crv'] = 'secp256k1'
      return 'ES256K' 
    elif key['crv'] == 'P-256' :
      return 'ES256'
    elif key['crv'] == 'P-384' :
      return 'ES384'
    elif key['crv'] == 'P-521' :
      return 'ES512'
    else :
      raise Exception("Curve not supported")
  elif key['kty'] == 'RSA' :
    return 'RS256'
  else :
    raise Exception("Key type not supported")


def pub_key(key) :
    """
    extract public key from private key
    """
    key = json.loads(key) if isinstance(key, str) else key
    Key = jwk.JWK(**key) 
    return Key.export_public(as_dict=True)
    

def sign_jwt_vc(vc, issuer_vm , issuer_key, issuer_did, wallet_did, nonce) :
    """
    For issuer

    https://jwcrypto.readthedocs.io/en/latest/jwk.html
    https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

    """
    issuer_key = json.loads(issuer_key) if isinstance(issuer_key, str) else issuer_key
    vc = json.loads(vc) if isinstance(vc, str) else vc
    signer_key = jwk.JWK(**issuer_key) 
    header = {
      'typ' :'JWT',
      'kid': issuer_vm,
      'alg': alg(issuer_key)
    }
    # TODO clean vc 
    payload = {
      'iss' : issuer_did,
      'nonce' : nonce,
      'iat': datetime.timestamp(datetime.now()),
      'nbf' : datetime.timestamp(datetime.now()),
      'jti' : vc['id'],
      'exp': datetime.timestamp(datetime.now()) + 1000,
      'sub' : wallet_did,
      'vc' : vc
    }  
    token = jwt.JWT(header=header,claims=payload, algs=[alg(issuer_key)])
    token.make_signed_token(signer_key)
    return token.serialize()


"""
For holder/wallet
Build and sign verifiable presentation as vp_token
Ascii is by default in the json string 
"""
def sign_jwt_vp(vc, audience, holder_vm, holder_did, nonce, vp_id, holder_key) :
    holder_key = json.loads(holder_key) if isinstance(holder_key, str) else holder_key
    signer_key = jwk.JWK(**holder_key) 
    header = {
        "typ" :"JWT",
        "alg": alg(holder_key),
        "kid" : holder_vm,
        "jwk" : pub_key(holder_key),
    }
    iat = round(datetime.timestamp(datetime.now()))
    payload = {
        "iat": iat,
        "jti" : vp_id,
        "nbf" : iat -10,
        "aud" : audience,
        "exp": iat + 1000,
        "sub" : holder_did,
        "iss" : holder_did,
        "vp" : {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": vp_id,
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc]
        },
        "nonce": nonce
    }
    token = jwt.JWT(header=header,claims=payload, algs=[alg(holder_key)])
    token.make_signed_token(signer_key)
    return token.serialize()


def verif_token(token, nonce) :
  """
  For issuer 
  raise exception if problem
  pub _key is in header
  https://jwcrypto.readthedocs.io/en/latest/jwt.html#jwcrypto.jwt.JWT.validate
  """
  header = get_header_from_token(token)
  payload = get_payload_from_token(token)
  if payload['nonce'] != nonce :
    raise Exception("Nonce is incorrect")
  a =jwt.JWT.from_jose_token(token)
  if isinstance (header['jwk'], str) :
    header['jwk'] = json.loads(header['jwk'])
  issuer_key = jwk.JWK(**header['jwk']) 
  a.validate(issuer_key)
  return


def verify_jwt_credential(token, pub_key) :
  """
  For verifier and holder
  raise an exception if problem
  pub_key is not in header
  https://jwcrypto.readthedocs.io/en/latest/jwt.html#jwcrypto.jwt.JWT.validate
  """
  a =jwt.JWT.from_jose_token(token)
  pub_key = json.loads(pub_key) if isinstance(pub_key, str) else pub_key
  issuer_key = jwk.JWK(**pub_key) 
  a.validate(issuer_key)
  return


def get_payload_from_token(token) :
  """
  For verifier
  check the signature and return None if failed
  """
  payload = token.split('.')[1]
  payload += "=" * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
  return json.loads(base64.urlsafe_b64decode(payload).decode())
 

def get_header_from_token(token) :
  header = token.split('.')[0]
  header += "=" * ((4 - len(header) % 4) % 4) # solve the padding issue of the base64 python lib
  return json.loads(base64.urlsafe_b64decode(header).decode())


def build_proof_of_key_ownership(key, aud, nonce) :
  """
  For wallets natural person as jwk is added in header
  """
  key = json.loads(key) if isinstance(key, str) else key
  signer_key = jwk.JWK(**key) 
  signer_pub_key = signer_key.export(private_key=False, as_dict=True)
  did = generate_np_ebsi_did(key)
  vm = verification_method(did, key)
  header = {
    'typ' :'JWT',
    'alg': alg(key),
    'jwk' : signer_pub_key, # for natural person
    'kid' : vm # only for EBSI
  }
  payload = {
    'iss' : did,
    'nonce' : nonce,
    'iat': datetime.timestamp(datetime.now()),
    'aud' : aud
  }  
  token = jwt.JWT(header=header,claims=payload, algs=[alg(key)])
  token.make_signed_token(signer_key)
  return token.serialize()


def thumbprint(key) :
  key = json.loads(key) if isinstance(key, str) else key
  if key['crv'] == 'P-256K' :
    key['crv'] = 'secp256k1'
  signer_key = jwk.JWK(**key) 
  a = signer_key.thumbprint()
  a  += "=" * ((4 - len(a) % 4) % 4) 
  return base64.urlsafe_b64decode(a).hex()


def generate_lp_ebsi_did() :
    """
    for legal person as issuer
    """
    return  'did:ebsi:z' + base58.b58encode(b'\x01' + os.urandom(16)).decode()


def generate_np_ebsi_did(key) :
    """
    for natural person / wallet
    """
    key = json.loads(key) if isinstance(key, str) else key
    return  'did:ebsi:z' + base58.b58encode(b'\x02' + bytes.fromhex(thumbprint(key))).decode()


def verification_method(did, key) : # = kid
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    thumb_print = signer_key.thumbprint()
    return did + '#' + thumb_print


def did_resolve_lp(did) :
  """
  API v3
  Get DID document with EBSI API
  https://api-pilot.ebsi.eu/docs/apis/did-registry/latest#/operations/get-did-registry-v3-identifier
  """
  try :
    url = 'https://api-pilot.ebsi.eu/did-registry/v3/identifiers/' + did
    r = requests.get(url) 
  except :
    logging.error('cannot access API')
    return 
  if 399 < r.status_code < 500 :
    return 
  return r.json()


def get_lp_public_jwk(did, kid) :
  """
  Get the issuer DID document from EBSI then get the public key depending on the verification method (kid)
  """
  did_doc = did_resolve_lp(did)
  if not did_doc :
    return
  for key in did_doc['verificationMethod'] :
    if key['id'] == kid :
      return key['publicKeyJwk']
  return  
  

def get_issuer_registry_data(did) :
  """
  API v3
  Get issuer or verifier data with EBSI API
  https://api-pilot.ebsi.eu/docs/apis/trusted-issuers-registry/latest#/operations/get-trusted-issuers-registry-v3-issuers-issuer
  """
  try :
    url = 'https://api-pilot.ebsi.eu/trusted-issuers-registry/v3/issuers/' + did
    r = requests.get(url) 
  except :
    logging.error('Cannot access API')
    return 
  if 399 < r.status_code < 500 :
    logging.warning('API call failed, return code = %s', r.status_code)
    return
  try : 
    body = r.json()['attributes'][0]['body']
    return base64.urlsafe_b64decode(body).decode()
  except :
    logging.error('Registry invalid format')
    return



def did_resolve(did, key) :
  """
  https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
  """
  key = json.loads(key) if isinstance(key, str) else key
  did_document = {
    "@context": "https://w3id.org/did/v1",
    "id": did,
    "verificationMethod": [
      {
        "id": verification_method(did, key),
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": {
          "kty": key['kty'],
          "crv": key['crv'],
          "x": key["x"],
          "y": key["y"],
          "alg": alg(key)
        }
      }
    ],
    "authentication": [
      verification_method(did, key)
    ],
    "assertionMethod": [
      verification_method(did, key)
      ]
    }
  return json.dumps(did_document)


# JSON-LD sign
def sign_jsonld_vc(credential, key, did) :
  key = json.loads(key) if isinstance(key, str) else key
  issuer_key = jwk.JWK(**key) 
  if isinstance(credential, str) :
    credential = json.loads(credential)
  proof= {
    #'@context':'https://w3id.org/security/v2',
    "type": "EcdsaSecp256k1Signature2019",
    "created": datetime.now().replace(microsecond=0).isoformat() + 'Z',
    "verificationMethod": verification_method(did, key),
    "proofPurpose": "assertionMethod"
  }
  h = {'alg':alg(key),'b64':False,'crit':['b64']}
  jws_header = json.dumps(h).encode()

  normalized_doc   = jsonld.normalize(credential , {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
  normalized_proof = jsonld.normalize(proof, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
  doc_hash         = hashlib.sha256()
  proof_hash       = hashlib.sha256()

  doc_hash.update(normalized_doc.encode('utf-8'))
  proof_hash.update(normalized_proof.encode('utf-8'))

  encodedHeader = base64.urlsafe_b64encode(jws_header)
  to_sign = encodedHeader + b'.' + proof_hash.digest() + doc_hash.digest()

  jwstoken = jws.JWS(to_sign)
  jwstoken.add_signature(issuer_key, None, json_encode({'alg': alg(key)}))

  sig = json.loads(jwstoken.serialize())['signature']
  proof_jws =encodedHeader + b'..' + base64.urlsafe_b64encode(sig.encode())

  #TODO check that
  #proof['jws']  = proof_jws.decode()[:-2] 
  proof['jws']  = proof_jws.decode()
  try :
    del proof['@context']
  except :
    pass
  credential['proof'] = proof
  return json.dumps(credential)



########################## TEST VECTORS

# EBSI TEST VECTORS

alice_key = {
  "kty" : "EC",
  "d" : "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
  "use" : "sig",
  "crv" : "P-256",
  "x" : "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
  "y" : "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  "alg" : "ES256",
}

alice_DID = "did:ebsi:znxntxQrN369GsNyjFjYb8fuvU7g3sJGyYGwMTcUGdzuy"
KID       = "did:ebsi:znxntxQrN369GsNyjFjYb8fuvU7g3sJGyYGwMTcUGdzuy#qujALp4bIDg5qs4lGuG_1OLycbh3ZyUfL-SJwiM9YjQ",

"""
{'crv': 'P-256', 'd': 'fdoUpbYXqQwLdA59KAGjHDK-tfSwILl6KOgmUR-9G-E', 'kty': 'EC', 'x': 'swb4CEhlK9LVttgfhkTE3fyzh3CVJOJWZFwnpvws06w', 'y': '61sQzFW216xWdfXhWi7oHzLH7AW55Sb_cRnpvMt0o_c'}
did:ebsi:zmBbuRFdCyzo8YXxdFfiWiDm5SYbAAXM2Qks824hv1WKK
did:ebsi:zmBbuRFdCyzo8YXxdFfiWiDm5SYbAAXM2Qks824hv1WKK#kHl_qBhwIoW9hiQDYDVxxg4vDt6vbg-_YCHXY3Piwso


{'crv': 'secp256k1', 'd': 'btbbhfOMozv735FBv1vE7oajjrvgjOmFz0RPPrKGIhI', 'kty': 'EC', 'x': 'jueEqLxxzNYzjuitj-6wQVjMKHtbVkz336BWmrv2n5k', 'y': 'fy-awzXPdLe_AzKvDHWMWxpVvDsXv_jZ3WcOxdaZ5CQ'}
did:ebsi:ztMVxH9gTfWxLVePz348Rme8fZqNL5vn7wJ8Ets2fAgSX
did:ebsi:ztMVxH9gTfWxLVePz348Rme8fZqNL5vn7wJ8Ets2fAgSX#-wRjA5dN5TJvZH_epIsrzZvAt28DHwPXloQvMVWevqw


key = jwk.JWK.generate(kty='EC', crv='P-256')
key = jwk.JWK.generate(kty='EC', crv='secp256k1')
my_key = json.loads(key.export(private_key=True))   #doctest: +ELLIPSIS
print(my_key)
print(did_ebsi(my_key))
print(verification_method_ebsi(my_key))
"""
