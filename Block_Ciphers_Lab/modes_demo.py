
import json
import os
import struct
import math
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------
# Допоміжні функції: padding та ентропія
# ---------------------------------------------------------

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("Порожні дані")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > 16:
        raise ValueError("Некоректний PKCS7 padding")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Помилка перевірки PKCS7 padding")

    return data[:-pad_len]


def calculate_entropy(data: bytes) -> float:
    """Обчислює ентропію Шеннона для розподілу байтів."""
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def count_duplicate_blocks(data: bytes, block_size: int = 16) -> int:
    """Кількість повторів повних блоків шифротексту."""
    blocks = [
        data[i:i + block_size]
        for i in range(0, len(data) - block_size + 1, block_size)
    ]

    return len(blocks) - len(set(blocks))


# ---------------------------------------------------------
# Частина 1. AES-128: ECB, CBC, CTR
# ---------------------------------------------------------

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    padded = pad_pkcs7(plaintext)

    return encryptor.update(padded) + encryptor.finalize()


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    return unpad_pkcs7(decrypted)


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padded = pad_pkcs7(plaintext)

    return encryptor.update(padded) + encryptor.finalize()


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    return unpad_pkcs7(decrypted)


def encrypt_ctr(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_ctr(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------
# Частина 2. Створення тестового BMP-зображення
# ---------------------------------------------------------

def create_test_bmp(width: int, height: int, path: str) -> None:
    """Створює 24-бітне BMP із однотонним фоном і центральним прямокутником."""

    row_size = (width * 3 + 3) & ~3
    pixel_data_size = row_size * height
    file_size = 54 + pixel_data_size

    header = struct.pack(
        "<2sIHHIIIIHHIIIIII",
        b"BM",
        file_size,
        0,
        0,
        54,
        40,
        width,
        height,
        1,
        24,
        0,
        pixel_data_size,
        2835,
        2835,
        0,
        0
    )

    pixels = bytearray(pixel_data_size)

    for y in range(height):
        for x in range(width):
            offset = y * row_size + x * 3

            if (
                width // 3 < x < 2 * width // 3
                and height // 3 < y < 2 * height // 3
            ):
                color = (255, 0, 0)
            else:
                color = (200, 200, 200)

            pixels[offset:offset + 3] = bytes(color)

    with open(path, "wb") as file:
        file.write(header)
        file.write(pixels)


def extract_pixel_data(path: str) -> tuple[bytes, bytes]:
    with open(path, "rb") as file:
        data = file.read()

    return data[:54], data[54:]


def save_encrypted_bmp(
    header: bytes,
    ciphertext: bytes,
    path: str
) -> None:
    """Зберігає зашифровані байти після BMP-заголовка."""

    new_header = bytearray(header)

    file_size = len(header) + len(ciphertext)

    struct.pack_into("<I", new_header, 2, file_size)
    struct.pack_into("<I", new_header, 34, len(ciphertext))

    with open(path, "wb") as file:
        file.write(new_header)
        file.write(ciphertext)


# ---------------------------------------------------------
# Частина 3. Атака Two-Time Pad на CTR
# ---------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def demonstrate_two_time_pad(
    key: bytes,
    nonce: bytes,
    message_a: bytes,
    message_b: bytes
) -> dict:

    max_len = max(len(message_a), len(message_b))

    message_a_padded = message_a.ljust(max_len, b"\x00")
    message_b_padded = message_b.ljust(max_len, b"\x00")

    ciphertext_a = encrypt_ctr(key, nonce, message_a_padded)
    ciphertext_b = encrypt_ctr(key, nonce, message_b_padded)

    xor_ciphertexts = xor_bytes(ciphertext_a, ciphertext_b)
    xor_plaintexts = xor_bytes(message_a_padded, message_b_padded)

    return {
        "ciphertext_a": ciphertext_a.hex(),
        "ciphertext_b": ciphertext_b.hex(),
        "xor_of_ciphertexts": xor_ciphertexts.hex(),
        "xor_of_plaintexts": xor_plaintexts.hex(),
        "attack_successful": xor_ciphertexts == xor_plaintexts
    }


# ---------------------------------------------------------
# Головна програма
# ---------------------------------------------------------

def main():
    with open("variant_9.json", "r", encoding="utf-8") as file:
        variant = json.load(file)

    key = bytes.fromhex(variant["aes_key_hex"])
    width = variant["image_width"]
    height = variant["image_height"]

    message_a = variant["message_a"].encode("utf-8")
    message_b = variant["message_b"].encode("utf-8")

    print("=" * 65)
    print("ЛАБОРАТОРНА РОБОТА №7 — AES ТА РЕЖИМИ ФУНКЦІОНУВАННЯ")
    print("=" * 65)

    print(f"Варіант: {variant['variant']}")
    print(f"AES-ключ: {key.hex()}")
    print(f"Розмір BMP: {width}x{height}")

    # Частина 1
    print("\nЧАСТИНА 1. РЕЖИМИ ECB, CBC, CTR")

    plaintext = b"Confidential financial report Q3 2026: revenue up 12 percent."

    ecb_ciphertext = encrypt_ecb(key, plaintext)
    ecb_decrypted = decrypt_ecb(key, ecb_ciphertext)

    iv = os.urandom(16)
    cbc_ciphertext = encrypt_cbc(key, iv, plaintext)
    cbc_decrypted = decrypt_cbc(key, iv, cbc_ciphertext)

    nonce = os.urandom(16)
    ctr_ciphertext = encrypt_ctr(key, nonce, plaintext)
    ctr_decrypted = decrypt_ctr(key, nonce, ctr_ciphertext)

    print(f"ECB: {ecb_ciphertext[:32].hex()}")
    print(f"CBC: {cbc_ciphertext[:32].hex()}")
    print(f"CTR: {ctr_ciphertext[:32].hex()}")

    print(f"ECB дешифрування правильне: {ecb_decrypted == plaintext}")
    print(f"CBC дешифрування правильне: {cbc_decrypted == plaintext}")
    print(f"CTR дешифрування правильне: {ctr_decrypted == plaintext}")

    print(f"Розмір відкритого тексту: {len(plaintext)} байт")
    print(f"Розмір CTR-шифротексту: {len(ctr_ciphertext)} байт")

    # Частина 2
    print("\nЧАСТИНА 2. ШИФРУВАННЯ BMP")

    create_test_bmp(width, height, "test_original.bmp")
    header, pixels = extract_pixel_data("test_original.bmp")

    ecb_pixels = encrypt_ecb(key, pixels)

    cbc_iv = os.urandom(16)
    cbc_pixels = encrypt_cbc(key, cbc_iv, pixels)

    save_encrypted_bmp(
        header, ecb_pixels, "test_encrypted_ecb.bmp"
    )

    save_encrypted_bmp(
        header, cbc_pixels, "test_encrypted_cbc.bmp"
    )

    with open("cbc_iv.bin", "wb") as file:
        file.write(cbc_iv)

    dup_ecb = count_duplicate_blocks(ecb_pixels)
    dup_cbc = count_duplicate_blocks(cbc_pixels)

    entropy_ecb = calculate_entropy(ecb_pixels)
    entropy_cbc = calculate_entropy(cbc_pixels)

    print(f"Створено BMP: {width}x{height}")
    print(f"Розмір даних пікселів: {len(pixels)} байт")

    print("\nПорівняння режимів:")
    print(f"{'Показник':<30}{'ECB':>12}{'CBC':>12}")
    print("-" * 54)
    print(f"{'Повторювані блоки':<30}{dup_ecb:>12}{dup_cbc:>12}")
    print(f"{'Ентропія (біт/байт)':<30}{entropy_ecb:>12.4f}{entropy_cbc:>12.4f}")

    print("\nЗбережені файли:")
    print("test_original.bmp")
    print("test_encrypted_ecb.bmp")
    print("test_encrypted_cbc.bmp")
    print("cbc_iv.bin")

    # Частина 3
    print("\nЧАСТИНА 3. АТАКА TWO-TIME PAD НА CTR")

    shared_nonce = os.urandom(16)

    result = demonstrate_two_time_pad(
        key,
        shared_nonce,
        message_a,
        message_b
    )

    print(f"Повідомлення A: {variant['message_a']}")
    print(f"Повідомлення B: {variant['message_b']}")

    print(f"\nШифротекст A: {result['ciphertext_a']}")
    print(f"Шифротекст B: {result['ciphertext_b']}")

    print("\nCA XOR CB:")
    print(result["xor_of_ciphertexts"])

    print("\nMA XOR MB:")
    print(result["xor_of_plaintexts"])

    print(
        "\nАтака успішна:",
        result["attack_successful"]
    )


if __name__ == "__main__":
    main()
