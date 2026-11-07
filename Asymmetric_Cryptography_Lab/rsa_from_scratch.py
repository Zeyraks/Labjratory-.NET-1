
import json
import random
import time
from pathlib import Path


# ============================================================
# ЧАСТИНА 1. ТЕСТ ПРОСТОТИ МІЛЛЕРА—РАБІНА
# ============================================================

def miller_rabin_is_prime(n: int, rounds: int = 40) -> bool:
    """Перевіряє ймовірну простоту числа методом Міллера—Рабіна."""

    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    # Представляємо n - 1 у вигляді 2^s * d
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bit_length: int) -> int:
    """Генерує просте число заданої бітової довжини."""

    while True:
        candidate = random.getrandbits(bit_length)

        # Встановлюємо старший та молодший біти
        candidate |= (1 << (bit_length - 1)) | 1

        if miller_rabin_is_prime(candidate):
            return candidate


# ============================================================
# ЧАСТИНА 2. РОЗШИРЕНИЙ АЛГОРИТМ ЕВКЛІДА
# ============================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Повертає gcd та коефіцієнти Безу."""

    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = extended_gcd(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Знаходить обернений елемент d за модулем phi."""

    gcd, x, _ = extended_gcd(e, phi)

    if gcd != 1:
        raise ValueError(
            "Обернений елемент не існує: e і phi не взаємно прості."
        )

    return x % phi


# ============================================================
# ЧАСТИНА 3. МОДУЛЬНЕ ПІДНЕСЕННЯ ДО СТЕПЕНЯ
# ============================================================

def square_and_multiply(base: int, exponent: int, modulus: int) -> int:
    """Обчислює base^exponent mod modulus алгоритмом Square-and-Multiply."""

    if modulus <= 0:
        raise ValueError("Модуль повинен бути додатним.")

    result = 1
    base %= modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent //= 2

    return result


# ============================================================
# ЧАСТИНА 4. ГЕНЕРАЦІЯ КЛЮЧІВ RSA
# ============================================================

def generate_rsa_keypair(bit_length: int = 512) -> dict:
    """Генерує пару RSA-ключів заданої бітової довжини."""

    if bit_length < 16:
        raise ValueError("Розмір ключа повинен бути не менше 16 біт.")

    half_length = bit_length // 2

    while True:
        p = generate_prime(half_length)
        q = generate_prime(bit_length - half_length)

        if p == q:
            continue

        n = p * q

        # Повторюємо генерацію, якщо модуль має меншу довжину
        if n.bit_length() != bit_length:
            continue

        phi_n = (p - 1) * (q - 1)

        e = 65537

        if extended_gcd(e, phi_n)[0] != 1:
            e = 3

            while extended_gcd(e, phi_n)[0] != 1:
                e += 2

        d = mod_inverse(e, phi_n)

        return {
            "p": p,
            "q": q,
            "n": n,
            "phi_n": phi_n,
            "public_key": (e, n),
            "private_key": (d, n)
        }


# ============================================================
# ЧАСТИНА 5. ШИФРУВАННЯ ТА РОЗШИФРУВАННЯ RSA
# ============================================================

def rsa_encrypt(
    message_int: int,
    public_key: tuple[int, int]
) -> int:
    """Шифрує повідомлення: c = m^e mod n."""

    e, n = public_key

    if not (0 <= message_int < n):
        raise ValueError("Повідомлення повинно бути в діапазоні 0 <= m < n.")

    return square_and_multiply(message_int, e, n)


def rsa_decrypt(
    ciphertext_int: int,
    private_key: tuple[int, int]
) -> int:
    """Розшифровує повідомлення: m = c^d mod n."""

    d, n = private_key

    if not (0 <= ciphertext_int < n):
        raise ValueError("Шифротекст повинен бути в діапазоні 0 <= c < n.")

    return square_and_multiply(ciphertext_int, d, n)


# ============================================================
# ЧАСТИНА 6. ЗАВАНТАЖЕННЯ ІНДИВІДУАЛЬНОГО ВАРІАНТА
# ============================================================

def load_variant() -> dict:
    """Завантажує параметри з variant_9.json."""

    path = Path(__file__).with_name("variant_9.json")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# ДЕМОНСТРАЦІЯ
# ============================================================

def main():

    variant = load_variant()

    p = variant["rsa_small_p"]
    q = variant["rsa_small_q"]
    message = variant["rsa_test_message"]
    full_bit_length = variant["rsa_full_bit_length"]

    print("=" * 65)
    print("ЛАБОРАТОРНА РОБОТА №8. АСИМЕТРИЧНА КРИПТОГРАФІЯ")
    print("=" * 65)

    # --------------------------------------------------------
    # 1. Ручний приклад для варіанта №9
    # --------------------------------------------------------

    print("\n1. RSA: ІНДИВІДУАЛЬНИЙ НАВЧАЛЬНИЙ ПРИКЛАД")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 7

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = {n}")
    print(f"phi(n) = {phi_n}")

    if extended_gcd(e, phi_n)[0] != 1:
        print(f"e = {e} не підходить, оскільки НСД(e, phi) != 1")
        e = 5
        print(f"Вибрано нове значення e = {e}")

    d = mod_inverse(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)

    print(f"Відкритий ключ: (e, n) = {public_key}")
    print(f"Закритий ключ: (d, n) = ({d}, {n})")
    print(f"Перевірка d * e mod phi(n) = {(d * e) % phi_n}")

    # --------------------------------------------------------
    # 2. Шифрування та розшифрування
    # --------------------------------------------------------

    print("\n2. ШИФРУВАННЯ ТА РОЗШИФРУВАННЯ")

    ciphertext = rsa_encrypt(message, public_key)
    decrypted = rsa_decrypt(ciphertext, private_key)

    print(f"Початкове повідомлення: m = {message}")
    print(f"Шифротекст: c = {ciphertext}")
    print(f"Розшифроване повідомлення: m = {decrypted}")
    print(f"Результат правильний: {decrypted == message}")

    # --------------------------------------------------------
    # 3. Перевірка тесту Міллера—Рабіна
    # --------------------------------------------------------

    print("\n3. ТЕСТ ПРОСТОТИ МІЛЛЕРА—РАБІНА")

    test_numbers = [97, 100, 561, 7919, 8000]

    for number in test_numbers:
        result = miller_rabin_is_prime(number, rounds=20)
        status = "просте" if result else "складене"
        print(f"{number}: {status}")

    # --------------------------------------------------------
    # 4. Генерація повної пари ключів RSA
    # --------------------------------------------------------

    print("\n4. ГЕНЕРАЦІЯ ПОВНОЇ ПАРИ RSA-КЛЮЧІВ")

    print(f"Індивідуальний розмір ключа: {full_bit_length} біт")

    start = time.perf_counter()
    keypair = generate_rsa_keypair(full_bit_length)
    elapsed = time.perf_counter() - start

    print(f"p ({keypair['p'].bit_length()} біт) = {keypair['p']}")
    print(f"q ({keypair['q'].bit_length()} біт) = {keypair['q']}")
    print(f"n ({keypair['n'].bit_length()} біт) = {keypair['n']}")
    print(f"Відкритий показник e = {keypair['public_key'][0]}")
    print(f"Довжина приватного показника d: "
          f"{keypair['private_key'][0].bit_length()} біт")
    print(f"Час генерації ключів: {elapsed:.6f} секунд")

    # Перевірка згенерованої пари ключів
    test_message = 123456789012345

    encrypted = rsa_encrypt(test_message, keypair["public_key"])
    decrypted_full = rsa_decrypt(encrypted, keypair["private_key"])

    print(f"Перевірка повної пари RSA: {decrypted_full == test_message}")

    # --------------------------------------------------------
    # 5. Порівняння часу генерації
    # --------------------------------------------------------

    print("\n5. ПОРІВНЯННЯ ЧАСУ ГЕНЕРАЦІЇ RSA")

    for size in [256, 384, 512]:
        start = time.perf_counter()
        generate_rsa_keypair(size)
        elapsed = time.perf_counter() - start

        print(f"{size} біт: {elapsed:.6f} секунд")

    print("\nВИКОНАННЯ ЧАСТИНИ 1 ЗАВЕРШЕНО.")


if __name__ == "__main__":
    main()
