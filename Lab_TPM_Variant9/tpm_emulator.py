
import hashlib
import hmac
import os
import json


# ============================================================
# ЧАСТИНА 1. ЕМУЛЯЦІЯ БАНКУ PCR ТА ОПЕРАЦІЇ EXTEND
# ============================================================

class PCRBank:
    """Навчальна модель банку PCR-регістрів TPM 2.0."""

    NUM_PCRS = 24
    HASH_ALGORITHM = "sha256"
    DIGEST_SIZE = 32

    def __init__(self):
        # Після Cold Reset усі PCR мають нульове значення.
        self.registers = [
            b"\x00" * self.DIGEST_SIZE
            for _ in range(self.NUM_PCRS)
        ]

    def extend(self, pcr_index: int, measurement: bytes) -> bytes:
        """
        TPM2_PCR_Extend:
        PCR_new = SHA256(PCR_old || SHA256(Measurement))
        """

        if not (0 <= pcr_index < self.NUM_PCRS):
            raise ValueError(
                f"Некоректний індекс PCR: {pcr_index}"
            )

        measurement_hash = hashlib.sha256(measurement).digest()
        old_value = self.registers[pcr_index]

        new_value = hashlib.sha256(
            old_value + measurement_hash
        ).digest()

        self.registers[pcr_index] = new_value

        return new_value

    def read(self, pcr_index: int) -> bytes:
        if not (0 <= pcr_index < self.NUM_PCRS):
            raise ValueError("Некоректний індекс PCR")

        return self.registers[pcr_index]

    def read_hex(self, pcr_index: int) -> str:
        return self.read(pcr_index).hex()

    def digest_of_selection(
        self,
        pcr_indices: list[int]
    ) -> bytes:
        """
        Обчислення Policy Digest:
        Dpolicy = SHA256(PCR[a] || PCR[b] || ...)
        """

        for index in pcr_indices:
            if not (0 <= index < self.NUM_PCRS):
                raise ValueError(
                    f"Некоректний індекс PCR: {index}"
                )

        concatenated = b"".join(
            self.registers[index]
            for index in pcr_indices
        )

        return hashlib.sha256(concatenated).digest()


# ============================================================
# ЧАСТИНА 2. SEALING / UNSEALING
# ============================================================

class SealedBlob:
    """Навчальна модель запечатаного об'єкта TPM."""

    def __init__(
        self,
        ciphertext: bytes,
        mac: bytes,
        policy_pcr_indices: list[int],
        policy_digest_at_seal_time: bytes
    ):
        self.ciphertext = ciphertext
        self.mac = mac
        self.policy_pcr_indices = policy_pcr_indices
        self.policy_digest_at_seal_time = (
            policy_digest_at_seal_time
        )


def xor_keystream(data: bytes, key: bytes) -> bytes:
    """
    Спрощений навчальний потоковий шифр.
    Не призначений для захисту реальних секретів.
    """

    keystream = b""
    counter = 0

    while len(keystream) < len(data):
        block = hmac.new(
            key,
            counter.to_bytes(4, "big"),
            hashlib.sha256
        ).digest()

        keystream += block
        counter += 1

    return bytes(
        a ^ b
        for a, b in zip(data, keystream[:len(data)])
    )


def seal(
    secret: bytes,
    pcr_bank: PCRBank,
    policy_pcr_indices: list[int],
    storage_parent_key: bytes
) -> SealedBlob:
    """Запечатування секрету з прив'язкою до вибраних PCR."""

    # Крок 1–2. Обчислення дайджесту політики.
    d_policy = pcr_bank.digest_of_selection(
        policy_pcr_indices
    )

    # Крок 3. Отримання ключів шифрування та автентифікації.
    k_sym = hmac.new(
        storage_parent_key,
        b"sym" + d_policy,
        hashlib.sha256
    ).digest()

    k_mac = hmac.new(
        storage_parent_key,
        b"mac" + d_policy,
        hashlib.sha256
    ).digest()

    # Крок 4. Шифрування секрету.
    ciphertext = xor_keystream(secret, k_sym)

    # Крок 5. Формування HMAC для перевірки цілісності.
    public_area = (
        b"policy_pcrs="
        + str(policy_pcr_indices).encode()
    )

    mac = hmac.new(
        k_mac,
        public_area + d_policy + secret,
        hashlib.sha256
    ).digest()

    return SealedBlob(
        ciphertext,
        mac,
        policy_pcr_indices.copy(),
        d_policy
    )


def unseal(
    blob: SealedBlob,
    pcr_bank: PCRBank,
    storage_parent_key: bytes
) -> bytes:
    """Розпечатування секрету з перевіркою PCR-політики."""

    # Крок 1. Отримання поточного Policy Digest.
    current_d_policy = pcr_bank.digest_of_selection(
        blob.policy_pcr_indices
    )

    # Крок 2. Перевірка відповідності політики.
    if not hmac.compare_digest(
        current_d_policy,
        blob.policy_digest_at_seal_time
    ):
        raise PermissionError(
            "UNSEAL ВІДХИЛЕНО: поточний стан PCR "
            "не відповідає політиці, зафіксованій під час Sealing."
        )

    # Крок 3. Повторне отримання ключів.
    k_sym = hmac.new(
        storage_parent_key,
        b"sym" + current_d_policy,
        hashlib.sha256
    ).digest()

    k_mac = hmac.new(
        storage_parent_key,
        b"mac" + current_d_policy,
        hashlib.sha256
    ).digest()

    # Крок 4. Розшифрування секрету.
    secret = xor_keystream(blob.ciphertext, k_sym)

    # Крок 5. Перевірка цілісності.
    public_area = (
        b"policy_pcrs="
        + str(blob.policy_pcr_indices).encode()
    )

    expected_mac = hmac.new(
        k_mac,
        public_area + current_d_policy + secret,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(expected_mac, blob.mac):
        raise PermissionError(
            "UNSEAL ВІДХИЛЕНО: HMAC не збігається. "
            "Blob пошкоджено або підроблено."
        )

    return secret


# ============================================================
# ЧАСТИНА 3. ПОБУДОВА ЛАНЦЮГА ЗАВАНТАЖЕННЯ
# ============================================================

def build_platform(variant: dict) -> PCRBank:
    """
    Побудова легітимного ланцюга вимірювань:
    PCR 0 — BIOS;
    PCR 2 — Option ROM;
    PCR 4 — Bootloader;
    PCR 7 — Secure Boot.

    PCR 5 залишається нульовим, оскільки в цьому завданні
    окремий компонент для нього не заданий.
    """

    bank = PCRBank()

    boot_chain = [
        (
            0,
            f"BIOS/UEFI firmware {variant['bios_version']}"
        ),
        (
            2,
            f"Option ROM: {variant['option_rom']}"
        ),
        (
            4,
            f"Bootloader: {variant['bootloader']}"
        ),
        (
            7,
            "Secure Boot state: enabled"
        )
    ]

    print("\nПослідовне вимірювання компонентів:")

    for pcr_index, component in boot_chain:
        new_value = bank.extend(
            pcr_index,
            component.encode("utf-8")
        )

        print(
            f"PCR[{pcr_index}] -> "
            f"{new_value.hex()}"
        )

    return bank


def print_pcr_bank(bank: PCRBank):
    print("\nПоточні значення PCR:")

    for index in [0, 2, 4, 5, 7]:
        print(
            f"PCR[{index}]: {bank.read_hex(index)}"
        )


def save_blob(blob: SealedBlob):
    """Збереження демонстраційного Sealed Blob у JSON."""

    data = {
        "ciphertext": blob.ciphertext.hex(),
        "mac": blob.mac.hex(),
        "policy_pcr_indices": blob.policy_pcr_indices,
        "policy_digest_at_seal_time":
            blob.policy_digest_at_seal_time.hex()
    }

    with open(
        "sealed_blob.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(data, file, indent=4)

    print("Sealed Blob збережено у sealed_blob.json")


# ============================================================
# ЧАСТИНА 4. ОСНОВНА ДЕМОНСТРАЦІЯ
# ============================================================

def main():

    print("=" * 70)
    print("ЛАБОРАТОРНА РОБОТА №10")
    print("ЕМУЛЯТОР КЛЮЧОВИХ ОПЕРАЦІЙ TPM 2.0")
    print("=" * 70)

    # Завантаження індивідуального варіанта.
    with open(
        "variant_9.json",
        "r",
        encoding="utf-8"
    ) as file:
        variant = json.load(file)

    policy_pcrs = variant["policy_pcrs"]
    secret = variant["secret"].encode("utf-8")

    print("\nІНДИВІДУАЛЬНІ ПАРАМЕТРИ")
    print("Варіант:", variant["variant"])
    print("BIOS:", variant["bios_version"])
    print("Option ROM:", variant["option_rom"])
    print("Bootloader:", variant["bootloader"])
    print("Політика Sealing:", policy_pcrs)
    print("Сценарій атаки:", variant["attack_description"])
    print("Уражений PCR:", variant["attack_pcr_index"])

    # Генерація навчального батьківського ключа.
    storage_parent_key = os.urandom(32)

    # --------------------------------------------------------
    # 1. ЛЕГІТИМНИЙ ЛАНЦЮГ ВИМІРЮВАНЬ
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("1. ЛЕГІТИМНИЙ ЛАНЦЮГ ВИМІРЮВАНЬ")
    print("=" * 70)

    legitimate_bank = build_platform(variant)
    print_pcr_bank(legitimate_bank)

    # --------------------------------------------------------
    # 2. SEALING
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("2. SEALING СЕКРЕТУ")
    print("=" * 70)

    blob = seal(
        secret,
        legitimate_bank,
        policy_pcrs,
        storage_parent_key
    )

    print("Політика PCR:", blob.policy_pcr_indices)
    print(
        "Policy Digest:",
        blob.policy_digest_at_seal_time.hex()
    )
    print("Ciphertext:", blob.ciphertext.hex())
    print("HMAC:", blob.mac.hex())

    save_blob(blob)

    # --------------------------------------------------------
    # 3. ЛЕГІТИМНЕ UNSEALING
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("3. ЛЕГІТИМНЕ UNSEALING")
    print("=" * 70)

    restored_secret = unseal(
        blob,
        legitimate_bank,
        storage_parent_key
    )

    print("Початковий секрет:", secret.decode("utf-8"))
    print("Відновлений секрет:", restored_secret.decode("utf-8"))
    print(
        "Секрети збігаються:",
        restored_secret == secret
    )

    # --------------------------------------------------------
    # 4. АТАКА: ВІДКАТ BIOS (PCR 0)
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("4. АТАКА: ВІДКАТ BIOS ДО ВРАЗЛИВОЇ ВЕРСІЇ")
    print("=" * 70)

    attacked_variant = variant.copy()
    attacked_variant["bios_version"] = "v1.00.0 (vulnerable)"

    attacked_bank = build_platform(attacked_variant)

    print("\nПорівняння PCR 0:")
    print("Легітимний:", legitimate_bank.read_hex(0))
    print("Після атаки:", attacked_bank.read_hex(0))

    try:
        unseal(
            blob,
            attacked_bank,
            storage_parent_key
        )

        print("ПОМИЛКА: Unseal пройшов успішно!")

    except PermissionError as error:
        print("РЕЗУЛЬТАТ:", error)
        print("Відкат BIOS виявлено. Секрет не розпечатано.")

    # --------------------------------------------------------
    # 5. АТАКА НА PCR 4, ЯКОГО НЕМАЄ В POLICY
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("5. АТАКА НА PCR, ЯКИЙ НЕ ВХОДИТЬ ДО ПОЛІТИКИ")
    print("=" * 70)

    excluded_pcr = 4

    print("Політика Sealing:", policy_pcrs)
    print("Змінюваний PCR:", excluded_pcr)

    if excluded_pcr in policy_pcrs:
        print(
            "PCR 4 входить до політики. "
            "Для демонстрації потрібно вибрати інший PCR."
        )
    else:
        modified_variant = variant.copy()
        modified_variant["bootloader"] = "Live USB Bootloader"

        modified_bank = build_platform(modified_variant)

        print("\nПорівняння PCR 4:")
        print("Легітимний:", legitimate_bank.read_hex(4))
        print("Після зміни:", modified_bank.read_hex(4))

        try:
            recovered = unseal(
                blob,
                modified_bank,
                storage_parent_key
            )

            print("\nUNSEAL УСПІШНИЙ!")
            print("Відновлений секрет:", recovered.decode("utf-8"))
            print("Секрети збігаються:", recovered == secret)

            print(
                "Причина: PCR 4 не входить до політики "
                "Sealing [0, 2, 5, 7]."
            )

        except PermissionError as error:
            print("UNSEAL ВІДХИЛЕНО:", error)

    print("\n" + "=" * 70)
    print("ВИКОНАННЯ ЛАБОРАТОРНОЇ РОБОТИ ЗАВЕРШЕНО")
    print("=" * 70)


if __name__ == "__main__":
    main()
