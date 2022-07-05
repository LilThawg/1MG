from pwn import *
from base64 import *
from Crypto.Util.Padding import *
def padding_oracle_attack (pre_block, mid_block, block):
    pre_block_fake = b'0'*16
    update = b''
    Dk = b''
    for i in range(15,-1,-1):
        for j in range(256):
            #brute-force c
            cj = bytes([j])
            pre_block_fake = pre_block_fake[:i] + cj + update 
            ciphertext_fake = base64.b64encode(pre_block_fake + mid_block + block)

            r.recvuntil(b'> ')
            r.sendline(b'2')
            r.recvuntil(b'Your username: ')
            r.sendline(b'')
            r.recvuntil(b'Your token: ')
            r.sendline(ciphertext_fake)
            resp = r.recvline()
            
            if b'Check your token again' not in resp:
                # Bước 1
                Dk = xor(bytes([16-i]), cj) + Dk
                P = xor(Dk, pre_block[i:])
                # Buớc 2
                P_fake_target = (16-i) * bytes([16-i+1])
                update = xor(Dk, P_fake_target)
                break
    
    return P, Dk

r = process(['python3','CBCBC.py'])
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Your username: ')
r.sendline(b'')
r.recvuntil(b'Your token: \n')
ciphertext = r.recvline().strip().decode()
print(f'[+] Token = {ciphertext}')
ciphertext = b64decode(ciphertext)
iv1, iv2, c1, c2, c3 = ciphertext[:16], ciphertext[16:32], ciphertext[32:48], ciphertext[48:64], ciphertext[64:96]

p1, Dkt1 = padding_oracle_attack(iv1, iv2, c1)
print(f'[+] p1 = {p1}')

s = 's_admin": true}'.encode()
possible_p3 = [pad(s[i:],16) for i in range(13)]

_, Dkt3 = padding_oracle_attack(c1, c2, c3)

possible_t2 = [xor(pos_p3, Dkt3) for pos_p3 in possible_p3]
possible_Dkc2 = [xor(pos_t2, c1) for pos_t2 in possible_t2]
possible_c1_xor_Dkc2 = possible_t2

for i in possible_c1_xor_Dkc2:
    _, Dkc1 = padding_oracle_attack(iv1, i, c2)
    t1 = xor(Dkc1, iv2)
    p2, _ = padding_oracle_attack(t1, c1, c2)
    print(f'[+] p2 possible: {p2}')

r.interactive()







