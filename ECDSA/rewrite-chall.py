from sage.all import *
from Crypto.Util.number import *
import hashlib

p = 6277101735386680763835789423207666416083908700390324961279
a = -3 
b = 2455155546008943817740293915197451784769108058161191238065

E = EllipticCurve(GF(p), [a, b])
gx = 602046282375688656758213480587526111916698976636884684818
gy = 174050332293622031404857552280219410364023488927386650641
G = E(gx, gy)
n = int(G.order())

class ECDSA():
    def __init__(self):
        self.dA = randrange(1, n) # private key
        self.QA = self.dA * G # public key
    
    def sha1(self, data):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.digest()

    def sign(self, msg):
        e = self.sha1(msg.encode())
        z = bytes_to_long(e)
        k = randrange(1, n-1) # nonce
        tmp_point = k*G
        x,y = tmp_point.xy()
        r = int(x) % n
        s = pow(k,-1,n) * (z + r * self.dA) % n 
        return r, s
    
    def verify(self, msg, r, s):
        e = self.sha1(msg.encode())
        z = bytes_to_long(e)
        u1 = z * pow(s, -1, n) % n
        u2 = r * pow(s, -1, n) % n
        tmp_point = u1 * G + u2 * self.QA
        x,y = tmp_point.xy()
        if r == int(x) % n:
            return True
        return False

chall = ECDSA()
r, s = chall.sign("lethethang")
print(chall.verify("lethethang", r, s))



