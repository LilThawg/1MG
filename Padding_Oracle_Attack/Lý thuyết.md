# PADDING ORACLE ATTACK

## Tổng quan

`Padding Oracle Attack` là một kỹ thuật tấn công phát lại (replay attack) khai thác điểm yếu của hệ mã chuỗi khối CBC (Cipher Block Chaining). CBC là một trong những kỹ thuật mã hóa khối, thực hiện mã hóa từng khối bản rõ của văn bản cần mã hóa. Đây là kỹ thuật tấn công chọn bản mã; với giả định là kẻ tấn công (attacker) tuy không biết giải mã, nhưng có thể tùy chỉnh thay đổi từng bản mã.

![image](https://lilthawg29.files.wordpress.com/2021/03/image-25.png)

Trong kỹ thuật tấn công này, attacker thực hiện replay attack tối đa 256 lần để xác định chính xác 1 byte trong một khối bản mã bất kỳ mà không cần quan tâm đến khóa bí mật, hay nói cách khác, chúng ta chỉ cần mỗi bản mã thôi :D
Kỹ thuật này khá giống với `blind sqli - boolean based` bên web đều là brute-force tối đa 256 lần đến khi kết quả trả về là `True` thì `break`, nhưng nó phức tạp hơn một chút.

## CBC mode

Trước khi đi sâu vào cách tấn công, ta hãy cùng tìm hiểu mã hoá AES mode CBC này hoạt động như nào:

![image](https://lilthawg29.files.wordpress.com/2021/03/image-26.png)

2 hình ảnh trên đã cho ta hình dung 1 ra mode CBC hoạt động như nào, chúng ta sẽ lấy 1 ví dụ cụ thể là AES-128 tức là key: 16 bytes và iv: 16 bytes, mỗi block cũng cho độ dài là 16 bytes luôn. 

Nếu độ dài bản rõ không đủ nó sẽ tự động padding thêm sao cho độ dài đầu vào là bội số của 16. Mặc định padding sẽ dùng [PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7)

![image](https://lilthawg29.files.wordpress.com/2021/03/image-6.png)

Giả sử len(P) = x, ta đặt y = (x // 16 + 1) * 16 là độ dài của P sau khi Padding. Đặt z = y – x (số bytes cần thêm vào cuối). Như vậy ta sẽ thêm vào cuối của P ban đầu z bytes có giá trị z. 

Ví dụ: độ dài input là `11` thì sẽ pad thêm `5` bytes `\x05`, còn nếu ộ dài input là `16` vừa tròn thì sẽ pad thêm `16` bytes `\x10` ('10' ở hệ 16 = 16). Nói đơn giản là thiếu 5 bytes thì thêm 5 bytes 5, đủ 16 bytes thì thêm 16 bytes 16 => thiếu x bytes thì thêm x bytes x.

## Sử dụng padding oracle attack khi nào ? 

Khi ta có một oracle để xác thực bằng cách kiểm tra xem padding liệu có đúng hay không.

## Tấn công

Phần tấn công ta sẽ đi vào bài làm cụ thể sẽ hiểu rõ hơn.

