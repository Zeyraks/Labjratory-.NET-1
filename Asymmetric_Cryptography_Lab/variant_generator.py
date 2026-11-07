
import json
import random
import sys

# Невеликі прості числа для ручного прикладу RSA
SMALL_PRIMES = [
    11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61
]

# Навчальні параметри Діффі—Геллмана
DH_SMALL_PARAMS = [
    (23, 5), (23, 7), (29, 2), (31, 3), (37, 2),
    (41, 6), (43, 3), (47, 5), (53, 2), (59, 2),
]

RSA_KEY_SIZES = [256, 384, 512]


def generate_variant(n: int) -> dict:
    if not (1 <= n <= 30):
        raise ValueError(
            "Номер варіанта має бути в діапазоні від 1 до 30"
        )

    rng = random.Random(n)

    # Пара простих чисел для ручного RSA
    p, q = rng.sample(SMALL_PRIMES, k=2)

    # Параметри Діффі—Геллмана
    dh_p, dh_g = DH_SMALL_PARAMS[n % len(DH_SMALL_PARAMS)]

    # Розмір повноцінного RSA-ключа
    rsa_bit_length = rng.choice(RSA_KEY_SIZES)

    # Тестове повідомлення
    max_message = p * q
    test_message = rng.randint(2, max_message - 1)

    return {
        "variant": n,
        "rsa_small_p": p,
        "rsa_small_q": q,
        "rsa_test_message": test_message,
        "rsa_full_bit_length": rsa_bit_length,
        "dh_p": dh_p,
        "dh_g": dh_g,
    }


def main():
    if len(sys.argv) != 2:
        print(
            "Використання: "
            "python3 variant_generator.py <номер_варіанта: 1-30>"
        )
        sys.exit(1)

    n = int(sys.argv[1])
    variant = generate_variant(n)

    out_path = f"variant_{n}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(variant, f, ensure_ascii=False, indent=2)

    print(f"Варіант №{n}")
    print("RSA (навчальний приклад): "
          f"p={variant['rsa_small_p']}, "
          f"q={variant['rsa_small_q']}, "
          f"n={variant['rsa_small_p'] * variant['rsa_small_q']}")

    print(
        "Тестове повідомлення для шифрування: "
        f"m={variant['rsa_test_message']}"
    )

    print(
        "Розмір ключа для повноцінної генерації RSA: "
        f"{variant['rsa_full_bit_length']} біт"
    )

    print(
        f"Діффі—Геллман: p={variant['dh_p']}, "
        f"g={variant['dh_g']}"
    )

    print(f"\nФайл створено: {out_path}")
    print(
        "Використайте rsa_from_scratch.py та "
        "diffie_hellman.py з цими параметрами."
    )


if __name__ == "__main__":
    main()
