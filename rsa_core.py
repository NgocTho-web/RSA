
"""
RSA CORE - THUẬT TOÁN RSA TỰ CODE
Không sử dụng thư viện bên ngoài.
Chỉ dùng cho mục đích học tập và mô phỏng.
"""


# =====================================
# 1. TÌM ƯỚC CHUNG LỚN NHẤT (GCD)
# =====================================
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# =====================================
# 2. THUẬT TOÁN EUCLID MỞ RỘNG
# =====================================
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


# =====================================
# 3. TÌM NGHỊCH ĐẢO MODULO
# =====================================
def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)

    if g != 1:
        raise ValueError(
            "Không tìm được nghịch đảo modulo."
        )

    return x % m


# =====================================
# 4. LŨY THỪA MODULO
# =====================================
def mod_pow(base, exponent, modulus):
    if modulus <= 0 or exponent < 0:
        raise ValueError("Tham số modulo không hợp lệ.")

    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent = exponent // 2

    return result


# =====================================
# 5. KIỂM TRA SỐ NGUYÊN TỐ
# =====================================
def is_prime(n):
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= n:
        if n % divisor == 0:
            return False

        divisor += 2

    return True


# =====================================
# 6. TỰ ĐỘNG TÍNH SỐ MŨ CÔNG KHAI e
# =====================================
def calculate_e(phi):
    # Ưu tiên e = 65537
    e = 65537

    if 1 < e < phi and gcd(e, phi) == 1:
        return e

    # Nếu 65537 không hợp lệ,
    # tìm số lẻ nhỏ nhất thỏa điều kiện
    e = 3

    while e < phi:
        if gcd(e, phi) == 1:
            return e

        e += 2

    raise ValueError(
        "Không tìm được số mũ công khai e hợp lệ."
    )


# =====================================
# 7. TẠO CẶP KHÓA RSA
# =====================================
def generate_keypair(p, q):

    # Kiểm tra p và q
    if not is_prime(p) or not is_prime(q):
        raise ValueError(
            "p và q phải là hai số nguyên tố."
        )

    if p == q:
        raise ValueError(
            "p và q phải khác nhau."
        )

    # Tính n
    n = p * q

    if n <= 255:
        raise ValueError(
            "p × q phải lớn hơn 255 để mã hóa UTF-8."
        )

    # Tính hàm Euler
    phi = (p - 1) * (q - 1)

    # Tự động chọn e
    e = calculate_e(phi)

    # Tự động tính d
    d = mod_inverse(e, phi)

    # Tạo Public Key
    public_key = (e, n)

    # Tạo Private Key
    private_key = (d, n)

    return public_key, private_key


# =====================================
# 8. MÃ HÓA THÔNG ĐIỆP RSA
# =====================================
def encrypt(message, public_key):

    e, n = public_key

    if e <= 1 or n <= 255:
        raise ValueError(
            "Public Key không hợp lệ."
        )

    if not message:
        raise ValueError(
            "Thông điệp không được để trống."
        )

    # Chuyển thông điệp sang UTF-8
    message_bytes = message.encode("utf-8")

    ciphertext = []

    # Mã hóa từng byte
    for byte in message_bytes:
        encrypted_byte = mod_pow(byte, e, n)
        ciphertext.append(encrypted_byte)

    return ciphertext


# =====================================
# 9. GIẢI MÃ THÔNG ĐIỆP RSA
# =====================================
def decrypt(ciphertext, private_key):

    d, n = private_key

    if d <= 0 or n <= 255:
        raise ValueError(
            "Private Key không hợp lệ."
        )

    if not ciphertext:
        raise ValueError(
            "Bản mã không được để trống."
        )

    plaintext_bytes = []

    for value in ciphertext:

        if value < 0 or value >= n:
            raise ValueError(
                "Bản mã có giá trị không hợp lệ."
            )

        decrypted_byte = mod_pow(value, d, n)

        if decrypted_byte > 255:
            raise ValueError(
                "Private Key không đúng hoặc bản mã bị lỗi."
            )

        plaintext_bytes.append(decrypted_byte)

    try:
        # Chuyển byte về chuỗi UTF-8
        plaintext = bytes(
            plaintext_bytes
        ).decode("utf-8")

        return plaintext

    except UnicodeDecodeError:
        raise ValueError(
            "Không thể giải mã UTF-8. "
            "Kiểm tra lại Private Key."
        )


# =====================================
# 10. CHUYỂN CHUỖI BẢN MÃ THÀNH DANH SÁCH
# =====================================
def parse_ciphertext(text):

    if not text.strip():
        raise ValueError(
            "Bản mã không được để trống."
        )

    try:
        ciphertext = []

        parts = text.replace(",", " ").split()

        for part in parts:
            ciphertext.append(int(part))

        return ciphertext

    except ValueError:
        raise ValueError(
            "Bản mã phải là các số nguyên "
            "cách nhau bằng dấu cách."
        )


# =====================================
# 11. CHUYỂN DANH SÁCH BẢN MÃ THÀNH CHUỖI
# =====================================
def ciphertext_to_string(ciphertext):
    return " ".join(str(value) for value in ciphertext)
