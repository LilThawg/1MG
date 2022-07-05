# Padding Oracle Attack 1 - KCSC

Chúng ta có 1 oracle có 2 chức năng `encrypt` và `decrypt`.
Func `encrypt` encrypt `FLAG` với `key` (không biết) và `iv` (có biết) :

```py
def encrypt(key):
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(pad(FLAG,16)) ).hex()
```

Func `decrypt` sẽ decrypt enc và check xem padding có hợp lệ hay không ?

```py
def decrypt(enc,key):
    enc = bytes.fromhex(enc)
    iv = enc[:16]
    ciphertext = enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if all(i == pad_len for i in decrypted[-pad_len:]):
        return b'Decrypted successfully.'
    else:
        return b'Incorrect padding.'
```

![image](./img/Screenshot%202022-07-02%20232453.png)

Vậy chỉ dựa vào 2 response `Decrypted successfully.` và `Incorrect padding.` làm sao ta có thể recover `FLAG` được ?

## Attack

Giả sử sau khi decrypt ta được `aaaaaaaaaaaaaaa\x01` hoặc `aaaaaaaaaaaaaa\x02\x02`,... nó sẽ coi là padding đúng, lợi dụng điều này ta sẽ thực hiện tấn công.

Chúng ta có :

- 3 Block : IV || C1 || C2 || C3
- Sử dụng padding PKCS#7
- Server trả lời True or False ?

Cần tìm :

- P1, P2 và P3

![image](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/900px-CBC_decryption.svg.png)

Từ nguyên tắc giải mã CBC, ta thấy rằng CBC thực hiện giải mã chỉ với 2 khối là khối hiện tại và khối trước đó, do đó ta chỉ cần đúng 2 khối để thực hiện tấn công phát lại.

Đối với bài này giả sử muốn recover P3 ta cần làm theo các bước sau:

**Bước 1 - Tìm từng byte P3** :

```
Ta có:
P3 = Dk(C3) ^ C2 (1)

Ta không cần chỉnh sửa khối C3 làm gì vì ta không biết key nên Dk(C3) ta không control được.
Tuy nhiên ta sẽ sửa C2, ký hiệu C2 sau khi sửa là C2_fake và kết quả là P3_fake ta được:
P3_fake = Dk(C3) ^ C2_fake (2)

(2) => Dk(C3) = P3_fake ^ C2_fake, thế vào (1) ta được:
P3 = P3_fake ^ C2_fake ^ C2 (3)

Điều này đúng với từng byte của các khối nên (2) => Dk(C3)[15] =  P3_fake[15] ^ C2_fake[15]
```

![image](https://samsclass.info/141/proj/p11pad7.png)

```
Nếu P3_fake[15] == 1 (\x01 đó) thì server response `Decrypted successfully.` do vậy ta sẽ:
Bruteforce tối đa 256 khả năng của C2_fake[15:16] đến khi nào server response `Decrypted successfully.` thì break.

Lúc này ta sẽ có cả C2_fake[15] (vừa bruteforce được),  P3_fake[15] = 1 ta sẽ tính được:
P3[15] = P3_fake[15] ^ C2_fake[15]           ^ C2[15]
          =      1   ^ vừa brute-force được  ^ có sẵn ngay từ đầu
```

![image](https://tlseminar.github.io/images/paddingoracle/last-word.png)

**Bước 2 : Thay đổi các byte đã tìm trước đó để chuẩn bị cho lần tìm tiếp theo**

Ta cần thay đổi byte cuối của P3_fake = b'\x02' để chuẩn bị cho việc 2 byte cuối của P3 là b'\x02\x02'.

\*lưu ý : đây là lần 1 nên chỉ sửa 1 byte cuối thành b'\x02', lần 2 thì sửa 2 byte cuối thành b'\x03\03',…

[Full script](./solve.py)
