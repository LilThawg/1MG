from pwn import *

def padding_oracle_attack (pre_block,block):
    pre_block_fake = b'a'*16
    update = b''
    Dk = b''
    for i in range(15,-1,-1):
        for j in range(256):
            #brute-force c
            cj = bytes([j])
            pre_block_fake = pre_block_fake[:i] + cj + update 
            ciphertext_fake = (pre_block_fake + block).hex()
            r.sendline(b'decrypt')
            r.recvuntil(b'Ciphertext: ')
            r.sendline(ciphertext_fake.encode())
            resp = r.recvline()
        
            if b'successfully' in resp:
                # Bước 1
                Dk = xor(bytes([16-i]), cj) + Dk
                P = xor(Dk, pre_block[i:])
                print(P)
                # Buớc 2
                P_fake_target = (16-i) * bytes([16-i+1])
                update = xor(Dk, P_fake_target)
                break
    return P
        
r = process(['python3','CBC.py'])
r.sendline(b'encrypt')
ciphertext = r.recvline().decode()
ciphertext = bytes.fromhex(ciphertext)
iv, c1, c2, c3 = ciphertext[:16], ciphertext[16:32], ciphertext[32:48], ciphertext[48:64]

p1 = padding_oracle_attack(iv, c1)
p2 = padding_oracle_attack(c1, c2)
p3 = padding_oracle_attack(c2, c3)

flag = p1+p2+p3
print(f'[+]FLAG: {flag}')
