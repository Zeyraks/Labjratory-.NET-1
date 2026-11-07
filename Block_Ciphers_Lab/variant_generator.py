
import json
import random
import sys

IMAGE_SIZES = [
    (90, 90),
    (120, 120),
    (150, 90),
    (100, 140),
    (135, 135)
]

MESSAGE_PAIRS = [
    (
        "Send 5000 dollars to account 44219",
        "Send 9000 dollars to account 77003"
    ),
    (
        "Approve wire transfer to vendor A",
        "Approve wire transfer to vendor B"
    ),
    (
        "Meeting confirmed for Monday 10am",
        "Meeting canceled please reschedule"
    ),
    (
        "Access granted to server room 3B",
        "Access denied to server room 3B"
    ),
    (
        "Bonus payment approved this month",
        "Bonus payment denied this month"
    ),
]


def generate_variant(n: int) -> dict:
    if not (1 <= n <= 30):
        raise ValueError("Номер варіанта має бути в діапазоні від 1 до 30")

    rng = random.Random(n)

    # AES-128: ключ довжиною 16 байтів
    aes_key_hex = bytes(
        rng.randint(0, 255) for _ in range(16)
    ).hex()

    # Розмір тестового зображення
    image_width, image_height = rng.choice(IMAGE_SIZES)

    # Індивідуальна пара повідомлень
    message_a, message_b = MESSAGE_PAIRS[n % len(MESSAGE_PAIRS)]

    # Кількість раундів і раундові ключі Фейстеля
    num_rounds = rng.choice([3, 4, 5])
    feistel_round_keys = [
        rng.randint(0, 15) for _ in range(num_rounds)
    ]

    # Початковий 8-бітний блок
    feistel_L0 = rng.randint(0, 15)
    feistel_R0 = rng.randint(0, 15)

    return {
        "variant": n,
        "aes_key_hex": aes_key_hex,
        "image_width": image_width,
        "image_height": image_height,
        "message_a": message_a,
        "message_b": message_b,
        "feistel_round_keys": feistel_round_keys,
        "feistel_L0": feistel_L0,
        "feistel_R0": feistel_R0,
    }


def main():
    if len(sys.argv) != 2:
        print("Використання: python3 variant_generator.py <номер_варіанта>")
        sys.exit(1)

    try:
        n = int(sys.argv[1])
        variant = generate_variant(n)
    except ValueError as error:
        print(f"Помилка: {error}")
        sys.exit(1)

    out_path = f"variant_{n}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(variant, f, ensure_ascii=False, indent=2)

    print(f"Варіант №{n}")
    print(f"AES-ключ (hex): {variant['aes_key_hex']}")
    print(
        "Розмір тестового BMP-контейнера: "
        f"{variant['image_width']}×{variant['image_height']}"
    )

    print("Пара повідомлень для атаки Two-Time Pad:")
    print(f"  A: '{variant['message_a']}'")
    print(f"  B: '{variant['message_b']}'")

    print(
        f"Мережа Фейстеля: {len(variant['feistel_round_keys'])} раундів"
    )
    print(
        "Раундові ключі:",
        [format(k, "04b") for k in variant["feistel_round_keys"]]
    )

    print(
        f"Вхідний блок: L0={format(variant['feistel_L0'], '04b')}, "
        f"R0={format(variant['feistel_R0'], '04b')}"
    )

    print(f"\nФайл створено: {out_path}")
    print("Використайте feistel_demo.py та modes_demo.py з цими параметрами.")


if __name__ == "__main__":
    main()
