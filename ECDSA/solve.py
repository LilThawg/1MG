from pwn import *
from sage.all import *
from Crypto.Util.number import *
import json
import hashlib

def sha1(data):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(data)
    return sha1_hash.digest()

def sign(msg, k, dA):
    e = sha1(msg.encode())
    z = bytes_to_long(e)
    tmp_point = k*G
    x,y = tmp_point.xy()
    r = int(x) % n
    s = pow(k,-1,n) * (z + r * dA) % n 
    return r, s

p = 6277101735386680763835789423207666416083908700390324961279
a = -3 
b = 2455155546008943817740293915197451784769108058161191238065

E = EllipticCurve(GF(p), [a, b])
gx = 602046282375688656758213480587526111916698976636884684818
gy = 174050332293622031404857552280219410364023488927386650641
G = E(gx, gy)
n = int(G.order())

conn = remote("socket.cryptohack.org", 13381)
conn.recvline()
conn.sendline(b'{"option": "sign_time"}')

data = conn.recvline().strip()
data_json = json.loads(data)
msg = data_json['msg']
z = bytes_to_long(sha1(msg.encode()))
r = int(data_json['r'], 0)
s = int(data_json['s'], 0)
S = int(msg.split(':')[1])

for k in range(1,S):
    x,y = (k*G).xy()
    if int(x) == r:
        dA = (s*k-z) % n * pow(r,-1,n) % n
        msg = 'unlock'
        r1, s1 = sign(msg, k, dA)
        payload = {"option": "verify", "msg": msg, "r": hex(r1)[2:], "s": hex(s1)[2:]}
        print(f'{payload = }')
        payload = json.dumps(payload)
        conn.sendline(payload.encode())
        conn.interactive()
        break



        


