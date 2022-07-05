# Padding Oracle Attack 3

![image](./img/Screenshot%202022-07-05%20113703.png)

Bài này sử dụng mode IGE:
- Mã hoá: 
    - C1 = Ek(M1 ^ C0) ^ M0
    - C2 = Ek(M2 ^ C1) ^ M1
    - ...

- Giải mã:
    - M1 = Dk(C1 ^ M0) ^ C0
    - M2 = Dk(C2 ^ M1) ^ C1
    - ...

Làm qua 2 bài trên xong ta cũng thấy bài này đơn giản lúc đầu chỉ cần modified C0 để Padding Oracle tìm ra M1. Tìm được M1 ta lại thay vào để tìm tiếp M2, tương tự  thế với M3

[Script](./solve.py)