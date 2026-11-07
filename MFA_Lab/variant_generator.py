
import base64
import json
import random
import sys

DIGITS_OPTIONS = [6, 6, 6, 8]
STEP_OPTIONS = [30, 30, 60]
DRIFT_OPTIONS = [1, 1, 2]

AAA_SCENARIOS = [
    ("RADIUS", "Wi-Fi корпоративна мережа (WPA2-Enterprise, 802.1X)"),
    ("RADIUS", "VPN-шлюз віддаленого доступу співробітників"),
    ("TACACS+", "Адміністрування маршрутизаторів мережевого відділу (SSH)"),
    ("TACACS+", "Централізоване керування комутаторами дата-центру"),
    ("RADIUS", "Точки доступу гостьового Wi-Fi з порталом автентифікації"),
]


def generate_variant(n: int) -> dict:
    if not (1 <= n <= 30):
        raise ValueError("Номер варіанта має бути в діапазоні від 1 до 30")

    rng = random.Random(n)

    secret_bytes = bytes(rng.randint(0, 255) for _ in range(20))
    secret_b32 = base64.b32encode(secret_bytes).decode("utf-8")

    digits = rng.choice(DIGITS_OPTIONS)
    step = rng.choice(STEP_OPTIONS)
    drift = rng.choice(DRIFT_OPTIONS)

    protocol, scenario_desc = AAA_SCENARIOS[n % len(AAA_SCENARIOS)]

    p_factor1 = round(rng.uniform(0.01, 0.08), 3)
    p_factor2 = round(rng.uniform(0.0001, 0.005), 4)

    return {
        "variant": n,
        "secret_b32": secret_b32,
        "digits": digits,
        "step_seconds": step,
        "drift_windows": drift,
        "aaa_protocol": protocol,
        "aaa_scenario": scenario_desc,
        "p_password_compromise": p_factor1,
        "p_second_factor_compromise": p_factor2,
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

    print(f"Варіант №{n}")
    print(f"Секретний ключ (base32): {variant['secret_b32']}")
    print(
        f"Параметри TOTP: digits={variant['digits']}, "
        f"step={variant['step_seconds']}с, "
        f"drift_windows=±{variant['drift_windows']}"
    )
    print(
        f"Сценарій AAA: {variant['aaa_protocol']} – "
        f"{variant['aaa_scenario']}"
    )
    print(f"P(зламу пароля) = {variant['p_password_compromise']}")
    print(
        f"P(компрометації 2-го фактора) = "
        f"{variant['p_second_factor_compromise']}"
    )
    print(f"\nФайл створено: {out_path}")
    print("Використайте ці параметри для виклику totp() і verify_totp().")


if __name__ == "__main__":
    main()
