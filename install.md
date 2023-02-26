# Installation

## Requirements

Python 3.9+
Bootstrap 4.0+ -> https://getbootstrap.com/docs/4.0/getting-started/download/

## Install

mkdir ebsi-saas 
cd ebsi-saas
python3.10 -m venv venv 
. venv/bin/activate 
pip install redis
pip install Flask-Session
pip install Flask[async]
pip install  Flask-QRcode
pip install  jwcrypto
pip install base58
pip install pyld
pip install  gunicorn
pip install requests
pip install pkce

git init
git pull......

## Run

python main.py
