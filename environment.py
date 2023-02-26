import json
import logging
import socket

logging.basicConfig(level=logging.INFO)

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

	
class currentMode() :
	def __init__(self):
		self.test = True
		passwords = json.load(open('./passwords.json'))
		self.password = passwords['password']
		self.admin = passwords['admin_password']
		self.deeplink_talao = 'https://app.talao.co/'	
		self.deeplink_altme = 'https://app.altme.io/'			
		self.flaskserver = extract_ip()
		self.server = 'http://' + self.flaskserver + ':3000/'
		self.port = 3000
		

