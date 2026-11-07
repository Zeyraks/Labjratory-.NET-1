
import json
import random
import sys

BIOS_VERSIONS = [
    "v1.42.0",
    "v2.14.1",
    "v3.07.2",
    "v1.88.4",
    "v2.55.9"
]

BOOTLOADERS = [
    "GRUB 2.06",
    "Windows Boot Manager",
    "systemd-boot",
    "rEFInd 0.14",
    "GRUB 2.12"
]

OPTION_ROMS = [
    "NIC firmware v1.0",
    "RAID controller v3.2",
    "GPU VBIOS v2.1",
    "NVMe firmware v1.5"
]

MANDATORY_PCRS = [0, 7]
OPTIONAL_PCRS = [1, 2, 3, 4, 5]

ATTACK_SCENARIOS = [
    ("bootloader_swap", 4,
     "заміна легітимного завантажувача на Live USB"),

    ("bios_downgrade", 0,
     "відкат прошивки BIOS до вразливої версії"),

    ("secure_boot_disable", 7,
     "вимкнення Secure Boot у налаштуваннях BIOS"),

    ("option_rom_tamper", 2,
     "підміна прошивки мережевої картки (Option ROM)")
]

SECRET_PREFIXES = [
    "DISK_VOLUME_KEY",
    "BITLOCKER_MASTER_KEY",
    "LUKS_MASTER_KEY",
    "FDE_ENCRYPTION_KEY"
]


def generate_variant(n: int) -> dict:
    if not (1 <= n <= 30):
        raise ValueError(
            "Номер варіанта має бути в діапазоні від 1 до 30"
        )

    rng = random.Random(n)

    bios_version = rng.choice(BIOS_VERSIONS)
    bootloader = rng.choice(BOOTLOADERS)
    option_rom = rng.choice(OPTION_ROMS)

    num_optional = rng.randint(1, 2)
    optional_selected = rng.sample(
        OPTIONAL_PCRS,
        k=num_optional
    )

    policy_pcrs = sorted(
        MANDATORY_PCRS + optional_selected
    )

    secret_prefix = rng.choice(SECRET_PREFIXES)
    secret_suffix = "".join(
        rng.choices("0123456789abcdef", k=16)
    )

    secret = f"{secret_prefix}_{secret_suffix}"

    attack_name, attack_pcr, attack_description = (
        ATTACK_SCENARIOS[n % len(ATTACK_SCENARIOS)]
    )

    return {
        "variant": n,
        "bios_version": bios_version,
        "bootloader": bootloader,
        "option_rom": option_rom,
        "policy_pcrs": policy_pcrs,
        "secret": secret,
        "attack_scenario": attack_name,
        "attack_pcr_index": attack_pcr,
        "attack_description": attack_description
    }


def main():
    if len(sys.argv) != 2:
        print(
            "Використання: "
            "python3 variant_generator.py <номер_варіанта>"
        )
        sys.exit(1)

    try:
        n = int(sys.argv[1])
        variant = generate_variant(n)
    except ValueError as error:
        print(f"Помилка: {error}")
        sys.exit(1)

    out_path = f"variant_{n}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            variant,
            f,
            ensure_ascii=False,
            indent=2
        )

    print(f"Варіант №{n}")
    print(
        f"BIOS: {variant['bios_version']}, "
        f"Bootloader: {variant['bootloader']}, "
        f"Option ROM: {variant['option_rom']}"
    )
    print(f"Політика Sealing (PCR): {variant['policy_pcrs']}")
    print(f"Секрет для запечатування: {variant['secret']}")
    print(
        f"Сценарій атаки: {variant['attack_description']} "
        f"(PCR {variant['attack_pcr_index']})"
    )

    print(f"\nФайл створено: {out_path}")
    print("Використайте tpm_emulator.py з цими параметрами.")


if __name__ == "__main__":
    main()
