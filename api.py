# coding=utf-8
#  產生 AES key

import yaml, requests
import base64, os, json
from Crypto.Cipher import AES


# Load and parse config file
config = yaml.load(file('config.yaml', 'r'))
encrypt = config['encrypt']
for k, v in encrypt.iteritems():
      encrypt[k] = v.replace(" ", '')

nonce = encrypt['nonce']
n, e = int(encrypt["n"], 16), int(encrypt["e"], 16)

def createSecretKey(size):
  return (''.join(map(lambda xx: (hex(ord(xx))[2:]), os.urandom(size))))[0:16]

def rsaEncrypt(text):
  text = text[::-1]
  rs = pow(int(text.encode('hex'), 16), e, n)
  return format(rs, 'x').zfill(256)

print("Generating secretKey for current session...")
secretKey = createSecretKey(16)
encSecKey = rsaEncrypt(secretKey)

def aesEncrypt(text, secKey):
  pad = 16 - len(text) % 16
  text = text + pad * chr(pad)
  encryptor = AES.new(secKey, 2, '0102030405060708')
  ciphertext = encryptor.encrypt(text)
  ciphertext = base64.b64encode(ciphertext)
  return ciphertext

def encrypted_request(text):
  encText = aesEncrypt(aesEncrypt(text, nonce), secretKey)
  data = {
    'params': encText,
    'encSecKey': encSecKey
  }
  return data

def req_netease(url, payload):
  data = encrypted_request(payload)
  r = requests.post(url, data = data, headers=headers)
  result = json.loads(r.text)
  if result['code'] != 200:
    return None
  return result

def req_netease_detail(songId):
  payload = '{"id":"%d","c":"[{\\"id\\":\\"%d\\"}]"}' % (songId, songId)
  data = req_netease('http://music.163.com/weapi/v3/song/detail?csrf_token=', payload)
  if data is None or data['songs'] is None or len(data['songs']) != 1:
    return None
  song =  data['songs'][0]
  return song

def req_netease_url(songId, rate):
  payload = '{"ids":"[%d]","br":%d,"csrf_token":""}' % (songId, rate)
  data = req_netease('http://music.163.com/weapi/song/enhance/player/url?csrf_token=', payload)
  if data is None or data['data'] is None or len(data['data']) != 1:
    return None
  
  song = data['data'][0]
  if song['code'] != 200 or song['url'] is None:
    return None
  song['url'] = song['url'].replace('http:', 'https:')
  song['url'] = song['url'].replace('m8.music', 'm7.music')
  return song
