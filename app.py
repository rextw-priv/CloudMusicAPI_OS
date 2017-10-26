# coding=utf-8

from flask import *

import api

from Crypto.Hash import SHA256
from random import randint
#from Crypto.PublicKey import RSA

import json
import yaml, requests
from OpenSSL import SSL
import ssl
from redis_session import RedisSessionInterface

from flask_sslify import SSLify

# Load and parse config file
config = yaml.load(open('config.yaml', 'r'))
encrypt = config['encrypt']
for k, v in encrypt.iteritems():
  encrypt[k] = v.replace(" ", '')

app = Flask(__name__, static_url_path='/static')
app.config['recaptcha'] = config['recaptcha']
app.debug = config['debug']
app.session_interface = RedisSessionInterface(config['redis'])

# https
if config['ssl']:
  context = SSL.Context(SSL.SSLv23_METHOD)
  context.use_privatekey_file('private.key')
  context.use_certificate_file('certificate.crt')
  sslify = SSLify(app, permanent=True)

nonce = encrypt['nonce']
n, e = int(encrypt["n"], 16), int(encrypt["e"], 16)

def req_recaptcha(response, remote_ip):
  r = requests.post('https://www.google.com/recaptcha/api/siteverify', data = {
    'secret': config['recaptcha']['secret'],
    'response': response,
    'remoteip': remote_ip
  });
  result = json.loads(r.text);
  print("req_recaptcha from %s, result: %s" % (remote_ip, r.text))
  return result['success']

def sign_request(songId, rate):
  h = SHA256.new()
  h.update(str(songId))
  h.update(str(rate))
  h.update(config["sign_salt"])
  return h.hexdigest()

def is_verified(session):
  if not config['recaptcha']:
    return True
  return 'verified' in session and session['verified'] > 0

def set_verified(session):
  if config['recaptcha']:
    session['verified'] = randint(10, 20)

def decrease_verified(session):
  if config['recaptcha']:
    session['verified'] -= 1;

@app.route("/")
def index():
  verified = is_verified(session)
  return render_template('index.j2', verified = verified)

@app.route("/backdoor")
def backdoor():
  if app.debug:
    set_verified(session)
  return 'ok!'

@app.route('/s/<path:path>')
def static_route(path):
  return app.send_static_file(path)

@app.route("/sign/<int:songId>/<int:rate>", methods=['POST'])
def generate_sign(songId, rate):
  if not is_verified(session):
    # 檢查 Google 驗證
    if 'g-recaptcha-response' not in request.form \
      or not req_recaptcha(
        request.form['g-recaptcha-response'],
        request.headers[config['ip_header']] if config['ip_header'] else request.remote_addr
      ):
      #
      return jsonify({"verified": is_verified(session), "errno": 2})

    set_verified(session)

  # 請求歌曲資訊, 然後簽名
  decrease_verified(session)
  song = api.req_netease_detail(songId)
  if song is None:
    return jsonify({"verified": is_verified(session), "errno": 1})
    
  return jsonify({
    "verified": True,
    "sign": sign_request(songId, rate),
    "song": {
      "id": song['id'],
      "name": song['name'],
      "artist": [{"id": a['id'], "name": a['name']} for a in song['ar']]
    }
  })

@app.route("/<int:songId>/<int:rate>/<sign>")
def get_song_url(songId, rate, sign):
  if sign_request(songId, rate) != sign:
    return abort(403)

  song = api.req_netease_url(songId, rate)
  if song is None:
    return abort(404)
  
  response = redirect(song['url'], code=302)
  response.headers["max-age"] = song['expi']
  return response

@app.route("/api/<int:songId>/<int:rate>")
def bot_get_song_url(songId, rate):
  if api.req_netease_url(songId, rate) is None:
    return jsonify({
      "success": "false",
  })
  song = api.req_netease_detail(songId)
  return jsonify({
    "sign": sign_request(songId, rate),
    "songId": songId,
    "rate": rate,
    "song": {
      "id": song['id'],
      "name": song['name'],
      "artist": [{"id": a['id'], "name": a['name']} for a in song['ar']]
    }
  })
if __name__ == "__main__":
  print("Running...")
  #app.run(host='0.0.0.0', port=port, ssl_context=('certificate.crt', 'private.key'))
  app.run(host='0.0.0.0', port=8080)
  