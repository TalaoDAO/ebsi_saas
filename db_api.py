import json
import uuid
import logging
import sqlite3
import random 
import string
import base58
import os
from jwcrypto import jwk
from ebsi_constante import client_data_pattern_ebsi

logging.basicConfig(level=logging.INFO)

def update_ebsi_verifier(client_id, data) :
    return update(client_id, data, 'ebsi_verifier.db')
def read_ebsi_verifier(client_id) :
    return read(client_id, 'ebsi_verifier.db')
def list_ebsi_verifier() :
    return list('ebsi_verifier.db')
def delete_ebsi_verifier(client_id) :
    return delete(client_id, 'ebsi_verifier.db')
def create_ebsi_verifier(mode) :
    return create('ebsi_verifier.db', mode)

def update_ebsi_issuer(client_id, data) :
    return update(client_id, data, 'ebsi_issuer.db')
def read_ebsi_issuer(client_id) :
    return read(client_id, 'ebsi_issuer.db')
def list_ebsi_issuer() :
    return list('ebsi_issuer.db')
def delete_ebsi_issuer(client_id) :
    return delete(client_id, 'ebsi_issuer.db')
def create_ebsi_issuer(mode) :
    return create('ebsi_issuer.db',mode)


def create(db, mode) :
    letters = string.ascii_lowercase
    data = client_data_pattern_ebsi
    data['client_id'] = ''.join(random.choice(letters) for i in range(10))
    data['tezid_proof_type'] = data['client_id']
    data['client_secret'] = str(uuid.uuid1())
    if db == 'ebsi_issuer.db' :
        data['issuer_landing_page'] = mode.server + 'ebsi/issuer/' + data['client_id']
    key = jwk.JWK.generate(kty="EC", crv="P-256", alg="ES256")
    data['jwk'] = key.export_private()
    data["did_ebsi"] = 'did:ebsi:z' + base58.b58encode(b'\x01' + os.urandom(16)).decode()
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = { "client_id" : data['client_id'] ,"data" :json.dumps(data)}
    try :
        c.execute("INSERT INTO client VALUES (:client_id, :data)", db_data)
    except :
        logging.error('DB error')
        return None
    conn.commit()
    conn.close()
    return data['client_id']



def update(client_id, data, db) :
    delete(client_id, db)
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = { "client_id" : client_id,
            "data" : data}
    try :
        c.execute("INSERT INTO client VALUES (:client_id, :data)", db_data)
    except :
        return None
    conn.commit()
    conn.close()


def read(client_id, db) :
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = { 'client_id' : client_id}
    c.execute('SELECT data FROM client WHERE client_id = :client_id ', db_data)
    client_data = c.fetchone()
    conn.close()
    if not client_data :
        return None
    return client_data[0]


def list(db) :
    """ Return list of username """
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT client_id, data FROM client")
    db_select = c.fetchall()
    conn.close()
    select = [item[1] for item in db_select]
    return select


def delete(client_id, db) :
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = {'client_id' : client_id}
    try :
        c.execute("DELETE FROM client WHERE client_id = :client_id " , db_data)
    except :
        return None
    conn.commit()
    conn.close()
    return True