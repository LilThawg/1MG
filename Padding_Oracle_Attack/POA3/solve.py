from pwn import *
#context.log_level = 'debug' 
def _xor_blocks(a, b):
        return bytes([x ^ y for x, y in zip(a, b)])

def padding_oracle_attack (c1, m0, c0):
    c0_fake = b'a'*16
    update = b''
    Dk = b''
    for i in range(15,-1,-1):
        for j in range(256):
            #brute-force c
            cj = bytes([j])
            c0_fake = c0_fake[:i] + cj + update

            data_fake = {'ciphertext': c1.hex(), 'm0': m0.hex(), 'c0': c0_fake.hex()}
            r.recvuntil(b'> ')
            r.sendline(b'2')
            r.recvuntil(b'Input JSON format {ciphertext: ciphertext, m0: m0, c0: c0} :')
            r.sendline(str(data_fake).encode())
            resp = r.recvline()

            if b"Can't decrypt the message." not in resp:
                # Bước 1
                Dk = _xor_blocks(bytes([16-i]), cj) + Dk
                P = _xor_blocks(Dk, c0[i:])
                print(P)
                # Buớc 2
                P_fake_target = (16-i) * bytes([16-i+1])
                update = _xor_blocks(Dk, P_fake_target)
                break
    return P

r = process(['python3','chall.py'])
r.recvuntil(b'> ')
r.sendline(b'1')
data = eval(r.recvline())

ciphertext = data['ciphertext']
m0 = data['m0']
c0 = data['c0']

ciphertext = bytes.fromhex(ciphertext)
m0 = bytes.fromhex(m0)
c0 = bytes.fromhex(c0)
c1 = ciphertext[:16]
c2 = ciphertext[16:32]
c3 = ciphertext[32:48]

m1 = padding_oracle_attack(c1, m0, c0)
m2 = padding_oracle_attack(c2, m1, c1)
m3 = padding_oracle_attack(c3, m2, c2)

flag = m1 + m2 + m3
print(f'[+]Flag: {flag}')
