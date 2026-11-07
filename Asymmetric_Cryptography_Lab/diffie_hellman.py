
import random


# ---------------------------------------------------------------------
# ЧАСТИНА 1. Базовий протокол Діффі-Хеллмана (DHKE)
# ---------------------------------------------------------------------

class DHParty:
    """Одна сторона протоколу Діффі-Хеллмана."""

    def __init__(self, name: str, p: int, g: int):
        self.name = name
        self.p = p
        self.g = g

        # Приватний ключ учасника
        self.private_key = random.randrange(2, p - 1)

        # Відкритий ключ: A = g^a mod p
        self.public_key = pow(g, self.private_key, p)

    def compute_shared_secret(self, other_public_key: int) -> int:
        """Обчислення спільного секрету."""
        return pow(other_public_key, self.private_key, self.p)


def run_dhke(p: int, g: int) -> dict:
    """Емуляція обміну ключами між сторонами A та B."""

    party_a = DHParty("A", p, g)
    party_b = DHParty("B", p, g)

    # Кожна сторона обчислює спільний секрет
    shared_secret_a = party_a.compute_shared_secret(party_b.public_key)
    shared_secret_b = party_b.compute_shared_secret(party_a.public_key)

    return {
        "p": p,
        "g": g,
        "private_a": party_a.private_key,
        "public_a": party_a.public_key,
        "private_b": party_b.private_key,
        "public_b": party_b.public_key,
        "shared_secret_a": shared_secret_a,
        "shared_secret_b": shared_secret_b,
        "keys_match": shared_secret_a == shared_secret_b
    }


# ---------------------------------------------------------------------
# ЧАСТИНА 2. Навчальна демонстрація атаки «Людина посередині» (MitM)
# ---------------------------------------------------------------------

def simulate_mitm_attack(p: int, g: int) -> dict:
    """
    Демонстрація підміни відкритих ключів у неавтентифікованому DHKE.

    Зловмисник створює два незалежні набори ключів:
    один для взаємодії зі стороною A, інший — зі стороною B.
    """

    party_a = DHParty("A", p, g)
    party_b = DHParty("B", p, g)

    # Дві незалежні ключові пари зловмисника
    attacker_for_a = DHParty("M-A", p, g)
    attacker_for_b = DHParty("M-B", p, g)

    # A отримує відкритий ключ зловмисника замість ключа B
    secret_a_with_m = party_a.compute_shared_secret(
        attacker_for_a.public_key
    )
    secret_m_with_a = attacker_for_a.compute_shared_secret(
        party_a.public_key
    )

    # B отримує інший відкритий ключ зловмисника замість ключа A
    secret_b_with_m = party_b.compute_shared_secret(
        attacker_for_b.public_key
    )
    secret_m_with_b = attacker_for_b.compute_shared_secret(
        party_b.public_key
    )

    return {
        "secret_a_with_m": secret_a_with_m,
        "secret_m_with_a": secret_m_with_a,
        "a_m_match": secret_a_with_m == secret_m_with_a,

        "secret_b_with_m": secret_b_with_m,
        "secret_m_with_b": secret_m_with_b,
        "b_m_match": secret_b_with_m == secret_m_with_b,

        "a_and_b_secrets_differ": secret_a_with_m != secret_b_with_m
    }


# ---------------------------------------------------------------------
# ДЕМОНСТРАЦІЯ РОБОТИ
# ---------------------------------------------------------------------

def main():
    # Індивідуальні параметри варіанта №9
    p = 59
    g = 2

    print("=" * 70)
    print("ЛАБОРАТОРНА РОБОТА №8. ЧАСТИНА 2")
    print("ПРОТОКОЛ ДІФФІ-ХЕЛЛМАНА ТА ДЕМОНСТРАЦІЯ MitM")
    print("=" * 70)

    print("\nІндивідуальні параметри варіанта №9:")
    print(f"p = {p}")
    print(f"g = {g}")

    # -----------------------------------------------------------------
    # Частина 1. Звичайний обмін ключами
    # -----------------------------------------------------------------

    print("\n" + "=" * 70)
    print("ЧАСТИНА 1. ЛЕГІТИМНИЙ ОБМІН КЛЮЧАМИ DHKE")
    print("=" * 70)

    result = run_dhke(p, g)

    print(f"Сторона A: приватний ключ a = {result['private_a']}")
    print(f"Сторона A: відкритий ключ A = {result['public_a']}")

    print(f"\nСторона B: приватний ключ b = {result['private_b']}")
    print(f"Сторона B: відкритий ключ B = {result['public_b']}")

    print("\nОбчислення спільного секрету:")
    print(f"Секрет сторони A: KA = {result['shared_secret_a']}")
    print(f"Секрет сторони B: KB = {result['shared_secret_b']}")

    print(f"\nПеревірка KA == KB: {result['keys_match']}")

    # -----------------------------------------------------------------
    # Частина 2. Демонстрація MitM
    # -----------------------------------------------------------------

    print("\n" + "=" * 70)
    print("ЧАСТИНА 2. АТАКА «ЛЮДИНА ПОСЕРЕДИНІ» (MitM)")
    print("=" * 70)

    attack_result = simulate_mitm_attack(p, g)

    print("\nВзаємодія між A та зловмисником M:")
    print(f"Секрет, обчислений стороною A: "
          f"{attack_result['secret_a_with_m']}")
    print(f"Секрет, обчислений M: "
          f"{attack_result['secret_m_with_a']}")
    print(f"Секрети збігаються: {attack_result['a_m_match']}")

    print("\nВзаємодія між B та зловмисником M:")
    print(f"Секрет, обчислений стороною B: "
          f"{attack_result['secret_b_with_m']}")
    print(f"Секрет, обчислений M: "
          f"{attack_result['secret_m_with_b']}")
    print(f"Секрети збігаються: {attack_result['b_m_match']}")

    print("\nПорівняння секретів:")
    print(f"Секрет A-M відрізняється від секрету B-M: "
          f"{attack_result['a_and_b_secrets_differ']}")

    print("\n" + "=" * 70)
    print("ВИСНОВОК")
    print("=" * 70)

    if result["keys_match"]:
        print("Звичайний обмін DHKE виконано успішно.")
        print("Сторони A та B отримали однаковий спільний секрет.")

    if (attack_result["a_m_match"]
            and attack_result["b_m_match"]
            and attack_result["a_and_b_secrets_differ"]):
        print("Демонстрація MitM пройшла успішно.")
        print("Зловмисник отримав окремий спільний секрет із кожною стороною.")
        print("Без автентифікації сторони не можуть перевірити,")
        print("кому насправді належить отриманий відкритий ключ.")

    print("\nВИКОНАННЯ ЧАСТИНИ 2 ЗАВЕРШЕНО.")


if __name__ == "__main__":
    main()
