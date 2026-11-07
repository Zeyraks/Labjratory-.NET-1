
import json

from stream_ciphers import (
    LFSR,
    lfsr_period,
    berlekemp_massey,
    RC4,
    frequency_test,
    runs_test,
    bits_to_str
)


def main():
    # Завантаження параметрів індивідуального варіанта
    with open("variant_9.json", "r", encoding="utf-8") as file:
        config = json.load(file)

    L = config["lfsr_length"]
    taps = config["lfsr_taps"]
    seed = config["lfsr_seed"]

    key = bytes.fromhex(config["rc4_key_hex"])
    plaintext = config["plaintext"].encode("utf-8")
    intercepted_length = config["intercepted_bits_length"]

    print("=" * 70)
    print("ЛАБОРАТОРНА РОБОТА №6")
    print("ПОТОКОВІ ШИФРИ ТА ГЕНЕРАТОРИ ПСЕВДОВИПАДКОВИХ ЧИСЕЛ")
    print("Варіант №", config["variant"])
    print("=" * 70)

    # ---------------------------------------------------------
    # ЧАСТИНА 1. LFSR
    # ---------------------------------------------------------

    print("\n1. ГЕНЕРАЦІЯ ПОСЛІДОВНОСТІ LFSR")
    print("-" * 70)

    theoretical_period = 2 ** L - 1
    measured_period = lfsr_period(seed, taps)

    print("Довжина регістра:", L)
    print("Початковий стан:", seed)
    print("Відводи:", taps)
    print("Теоретичний період:", theoretical_period)
    print("Виміряний період:", measured_period)

    print(
        "Перевірка максимального періоду:",
        measured_period == theoretical_period
    )

    lfsr = LFSR(seed, taps)
    full_sequence = lfsr.generate(measured_period)

    print("Повна послідовність:")
    print(bits_to_str(full_sequence))

    # ---------------------------------------------------------
    # ЧАСТИНА 2. БЕРЛЕКЕМПА-МЕССІ
    # ---------------------------------------------------------

    print("\n2. КРИПТОАНАЛІЗ LFSR")
    print("-" * 70)

    intercepted_bits = full_sequence[:intercepted_length]

    print("Перехоплена послідовність:")
    print(bits_to_str(intercepted_bits))
    print("Кількість перехоплених бітів:", len(intercepted_bits))

    recovered_L, recovered_taps = berlekemp_massey(
        intercepted_bits
    )

    print("Відновлена довжина L:", recovered_L)
    print("Відновлені відводи:", recovered_taps)

    print("Початкова довжина L:", L)
    print("Початкові відводи:", taps)

    print(
        "Збіг довжини:",
        recovered_L == L
    )

    print(
        "Збіг відводів:",
        recovered_taps == taps
    )

    # Перевірка відновленої послідовності
    if recovered_L > 0 and len(intercepted_bits) >= recovered_L:
        verify_lfsr = LFSR(
            intercepted_bits[:recovered_L],
            recovered_taps
        )

        predicted_sequence = verify_lfsr.generate(
            measured_period
        )

        print(
            "Збіг повної послідовності:",
            predicted_sequence == full_sequence
        )

    # ---------------------------------------------------------
    # ЧАСТИНА 3. RC4
    # ---------------------------------------------------------

    print("\n3. ШИФРУВАННЯ ТА РОЗШИФРУВАННЯ RC4")
    print("-" * 70)

    print("Ключ RC4:", config["rc4_key_hex"])
    print("Відкритий текст:", plaintext.decode("utf-8"))

    cipher = RC4(key)
    ciphertext = cipher.encrypt(plaintext)

    print("Шифротекст (HEX):")
    print(ciphertext.hex())

    decipher = RC4(key)
    decrypted = decipher.decrypt(ciphertext)

    print("Розшифрований текст:")
    print(decrypted.decode("utf-8"))

    print(
        "Коректність розшифрування:",
        decrypted == plaintext
    )

    # ---------------------------------------------------------
    # ЧАСТИНА 4. СТАТИСТИЧНІ ТЕСТИ
    # ---------------------------------------------------------

    print("\n4. СТАТИСТИЧНІ ТЕСТИ ГАМИ")
    print("-" * 70)

    # Для статистики використовуємо 2000 бітів
    stats_length = 2000

    # LFSR з параметрами індивідуального варіанта
    lfsr_stats = LFSR(seed, taps)
    lfsr_bits = lfsr_stats.generate(stats_length)

    # RC4 генерує 250 байтів = 2000 бітів
    rc4_stats = RC4(key)
    rc4_bytes = rc4_stats.keystream(stats_length // 8)

    rc4_bits = [
        (byte >> shift) & 1
        for byte in rc4_bytes
        for shift in range(7, -1, -1)
    ]

    results = []

    for name, bits in [
        ("LFSR", lfsr_bits),
        ("RC4", rc4_bits)
    ]:
        frequency = frequency_test(bits)
        runs = runs_test(bits)

        results.append({
            "name": name,
            "frequency": frequency,
            "runs": runs
        })

        print("\nГенератор:", name)

        print(
            "Частотний тест:",
            "одиниць =", frequency["ones"],
            "нулів =", frequency["zeros"],
            "частка одиниць =", frequency["proportion_ones"],
            "PASS =", frequency["passed"]
        )

        print(
            "Тест серій:",
            "усього серій =", runs["total_runs"],
            "серій довжини 1 =",
            runs["actual_ratio_length_1"]
        )

        print(
            "Розподіл довжин серій:",
            runs["length_distribution"]
        )

    # ---------------------------------------------------------
    # ПОРІВНЯЛЬНА ТАБЛИЦЯ
    # ---------------------------------------------------------

    print("\n5. ПОРІВНЯЛЬНА ТАБЛИЦЯ")
    print("-" * 70)

    print(
        f"{'Генератор':<12}"
        f"{'Одиниць':<12}"
        f"{'Нулів':<12}"
        f"{'Частка 1':<14}"
        f"{'Серій':<10}"
        f"{'Серій довж. 1':<16}"
    )

    for result in results:
        freq = result["frequency"]
        runs = result["runs"]

        print(
            f"{result['name']:<12}"
            f"{freq['ones']:<12}"
            f"{freq['zeros']:<12}"
            f"{freq['proportion_ones']:<14}"
            f"{runs['total_runs']:<10}"
            f"{runs['actual_ratio_length_1']:<16}"
        )

    print("\nЛабораторну роботу завершено.")


if __name__ == "__main__":
    main()
