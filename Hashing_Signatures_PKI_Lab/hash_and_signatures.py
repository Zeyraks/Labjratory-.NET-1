
import hashlib
import random


# ---------------------------------------------------------------------
# ЧАСТИНА 1. Лавинний ефект SHA-256
# ---------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hamming_distance_bits(hex_a: str, hex_b: str) -> int:
    """Підрахунок кількості бітів, що відрізняються."""
    int_a = int(hex_a, 16)
    int_b = int(hex_b, 16)
    xor_result = int_a ^ int_b
    return bin(xor_result).count("1")


def demonstrate_avalanche_effect(
    message: bytes,
    bit_position: int = 7
) -> dict:
    """Інвертує один біт першого байта повідомлення."""

    if not message:
        raise ValueError("Повідомлення не може бути порожнім.")

    if not 0 <= bit_position <= 7:
        raise ValueError("Позиція біта має бути від 0 до 7.")

    original_hash = sha256_hex(message)

    mutated = bytearray(message)
    mutated[0] ^= (1 << bit_position)

    mutated_hash = sha256_hex(bytes(mutated))

    diff_bits = hamming_distance_bits(
        original_hash,
        mutated_hash
    )

    total_bits = 256
    percentage = (diff_bits / total_bits) * 100

    return {
        "original_message": message,
        "original_hash": original_hash,
        "mutated_hash": mutated_hash,
        "differing_bits": diff_bits,
        "total_bits": total_bits,
        "percentage_changed": round(percentage, 2),
        "bit_position": bit_position
    }


# ---------------------------------------------------------------------
# ЧАСТИНА 2. Реалізація схеми підпису Шнорра
# ---------------------------------------------------------------------

class SchnorrSignature:
    """Навчальна реалізація схеми цифрового підпису Шнорра."""

    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g

    def generate_keypair(self) -> tuple[int, int]:
        """Генерація приватного та відкритого ключів."""
        x = random.randrange(1, self.q)
        y = pow(self.g, x, self.p)
        return x, y

    def _hash_challenge(self, message: bytes, t: int) -> int:
        """Обчислення хеш-виклику."""
        data = message + str(t).encode()
        digest = hashlib.sha256(data).hexdigest()
        return int(digest, 16) % self.q

    def sign(
        self,
        message: bytes,
        private_key: int,
        nonce_k: int = None
    ) -> tuple[int, int]:
        """Створення цифрового підпису."""

        r = (
            nonce_k
            if nonce_k is not None
            else random.randrange(1, self.q)
        )

        if not 1 <= r < self.q:
            raise ValueError("Nonce має бути в діапазоні від 1 до q-1.")

        t = pow(self.g, r, self.p)
        c = self._hash_challenge(message, t)
        s = (r - c * private_key) % self.q

        return c, s

    def verify(
        self,
        message: bytes,
        signature: tuple[int, int],
        public_key: int
    ) -> bool:
        """Перевірка цифрового підпису."""

        c, s = signature

        t_recovered = (
            pow(self.g, s, self.p)
            * pow(public_key, c, self.p)
        ) % self.p

        c_recomputed = self._hash_challenge(
            message,
            t_recovered
        )

        return c == c_recomputed


# ---------------------------------------------------------------------
# ЧАСТИНА 3. Демонстрація катастрофи Nonce
# ---------------------------------------------------------------------

def demonstrate_nonce_catastrophe(
    scheme: SchnorrSignature,
    private_key: int,
    message_1: bytes,
    message_2: bytes
) -> dict:
    """Навчальна демонстрація наслідків повторного використання k."""

    # Навмисне повторне використання одного nonce
    shared_k = random.randrange(1, scheme.q)

    c1, s1 = scheme.sign(
        message_1,
        private_key,
        nonce_k=shared_k
    )

    c2, s2 = scheme.sign(
        message_2,
        private_key,
        nonce_k=shared_k
    )

    q = scheme.q
    denom = (c2 - c1) % q

    if denom == 0:
        raise ValueError(
            "c1 дорівнює c2. Потрібно повторити демонстрацію."
        )

    denom_inv = pow(denom, -1, q)

    recovered_x = (
        (s1 - s2) * denom_inv
    ) % q

    return {
        "shared_nonce_k": shared_k,
        "signature_1": (c1, s1),
        "signature_2": (c2, s2),
        "recovered_private_key": recovered_x,
        "actual_private_key": private_key,
        "attack_successful": recovered_x == private_key
    }


# ---------------------------------------------------------------------
# ГОЛОВНА ФУНКЦІЯ
# ---------------------------------------------------------------------

def main():

    print("=" * 70)
    print("ЧАСТИНА 1. ЛАВИННИЙ ЕФЕКТ SHA-256")
    print("=" * 70)

    message = b"Release payment to vendor XYZ"

    result = demonstrate_avalanche_effect(
        message,
        bit_position=7
    )

    print(f"Оригінальне повідомлення: {result['original_message']}")
    print(f"Хеш оригіналу: {result['original_hash']}")
    print(f"Хеш після зміни біта: {result['mutated_hash']}")
    print(f"Позиція зміненого біта: {result['bit_position']}")
    print(
        f"Кількість змінених бітів: "
        f"{result['differing_bits']} з {result['total_bits']}"
    )
    print(
        f"Відсоток зміни: "
        f"{result['percentage_changed']}% (очікується близько 50%)"
    )

    print("\n" + "=" * 70)
    print("ЧАСТИНА 2. СХЕМА ПІДПИСУ ШНОРРА")
    print("=" * 70)

    # Навчальні параметри групи
    p, q, g = 467, 233, 4

    scheme = SchnorrSignature(p, q, g)

    private_key, public_key = scheme.generate_keypair()

    print(f"Параметри групи: p={p}, q={q}, g={g}")
    print(f"Приватний ключ x={private_key}")
    print(f"Публічний ключ y={public_key}")

    message = b"Contract: pay 100 UAH"

    signature = scheme.sign(message, private_key)

    print(f"\nПовідомлення: {message}")
    print(f"Підпис (c, s): {signature}")

    is_valid = scheme.verify(
        message,
        signature,
        public_key
    )

    print(
        "Перевірка підпису:",
        "ВАЛІДНИЙ" if is_valid else "НЕВАЛІДНИЙ"
    )

    # Перевірка підпису на зміненому повідомленні
    forged_message = b"Contract: pay 1000000 UAH"

    is_valid_forged = scheme.verify(
        forged_message,
        signature,
        public_key
    )

    print(
        "Перевірка підпису на іншому повідомленні:",
        "ВАЛІДНИЙ" if is_valid_forged
        else "НЕВАЛІДНИЙ (правильно)"
    )

    print("\n" + "=" * 70)
    print("ЧАСТИНА 3. КАТАСТРОФА NONCE")
    print("=" * 70)

    msg_a = b"Authorize refund request"
    msg_b = b"Deny refund request"

    attack = demonstrate_nonce_catastrophe(
        scheme,
        private_key,
        msg_a,
        msg_b
    )

    print(f"Повідомлення A: {msg_a}")
    print(f"Повідомлення B: {msg_b}")

    print(f"\nПовторно використаний nonce k: {attack['shared_nonce_k']}")
    print(f"Підпис повідомлення A: {attack['signature_1']}")
    print(f"Підпис повідомлення B: {attack['signature_2']}")

    print(
        "\nВідновлений приватний ключ:",
        attack["recovered_private_key"]
    )

    print(
        "Справжній приватний ключ:",
        attack["actual_private_key"]
    )

    print(
        "Результат демонстрації:",
        "УСПІШНО" if attack["attack_successful"]
        else "НЕВДАЛО"
    )


if __name__ == "__main__":
    main()
