
import json
import random
import sys

PRIMITIVE_POLYNOMIALS = {
    4: [0, 1],
    5: [0, 2],
    6: [0, 1],
    7: [0, 3],
    8: [0, 2, 3, 4],
}


def generate_variant(n: int) -> dict:
    if not (1 <= n <= 30):
        raise ValueError("Номер варіанта має бути в діапазоні від 1 до 30")

    rng = random.Random(n)

    L = rng.choice(list(PRIMITIVE_POLYNOMIALS.keys()))
    taps = PRIMITIVE_POLYNOMIALS[L]

    while True:
        seed = [rng.randint(0, 1) for _ in range(L)]
        if any(seed):
            break

    key_length = rng.randint(8, 16)
    rc4_key = bytes(rng.randint(0, 255) for _ in range(key_length))

    messages = [
        "Operation starts at midnight",
        "The package is on the way",
        "Confirm access to the vault",
        "Meeting rescheduled to Friday",
        "All systems are operational",
        "Transfer authorized by manager",
    ]

    plaintext = rng.choice(messages)

    intercepted_length = 2 * L + rng.choice([0, 2, 4])

    return {
        "variant": n,
        "lfsr_length": L,
        "lfsr_taps": taps,
        "lfsr_seed": seed,
        "rc4_key_hex": rc4_key.hex(),
        "plaintext": plaintext,
        "intercepted_bits_length": intercepted_length,
    }


def main():
    if len(sys.argv) != 2:
        print("Використання: python3 variant_generator.py <номер_варіанта: 1-30>")
        sys.exit(1)

    n = int(sys.argv[1])
    variant = generate_variant(n)

    out_path = f"variant_{n}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(variant, f, ensure_ascii=False, indent=2)

    L = variant["lfsr_length"]

    print(f"Варіант №{n}")
    print(
        f"LFSR: L={L}, taps={variant['lfsr_taps']}, "
        f"seed={variant['lfsr_seed']}"
    )
    print(f"Теоретичний період: 2^{L} - 1 = {2**L - 1}")
    print(
        "Кількість бітів для атаки Берлекемпа-Мессі: "
        f"{variant['intercepted_bits_length']}"
    )
    print(f"RC4-ключ (hex): {variant['rc4_key_hex']}")
    print(f"Повідомлення: '{variant['plaintext']}'")
    print(f"\nФайл створено: {out_path}")


if __name__ == "__main__":
    main()
