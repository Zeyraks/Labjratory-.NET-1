
import json


def to_bits(value: int, width: int = 4) -> str:
    return format(value, f"0{width}b")


def rotate_left_4(value: int, shift: int = 1) -> int:
    """Циклічний зсув вліво для 4-бітного числа."""
    shift %= 4
    return ((value << shift) | (value >> (4 - shift))) & 0b1111


def feistel_function(R: int, K: int) -> int:
    """F(R, K) = ROTLEFT4(R, 1) XOR K."""
    return rotate_left_4(R, 1) ^ K


def feistel_encrypt_block(L0: int, R0: int, keys: list[int]):
    """Шифрування блоку мережею Фейстеля."""
    L, R = L0, R0

    for i, K in enumerate(keys, start=1):
        F = feistel_function(R, K)
        new_L = R
        new_R = L ^ F

        print(
            f"Раунд {i}: K={to_bits(K)}, "
            f"F={to_bits(F)}, "
            f"L={to_bits(new_L)}, R={to_bits(new_R)}"
        )

        L, R = new_L, new_R

    return L, R


def feistel_decrypt_block(Ln: int, Rn: int, keys: list[int]):
    """Дешифрування зі зворотним порядком ключів."""
    L, R = Ln, Rn

    for K in reversed(keys):
        R_prev = L
        L_prev = R ^ feistel_function(L, K)
        L, R = L_prev, R_prev

    return L, R


def main():
    with open("variant_9.json", "r", encoding="utf-8") as f:
        variant = json.load(f)

    L0 = variant["feistel_L0"]
    R0 = variant["feistel_R0"]
    keys = variant["feistel_round_keys"]

    print("=" * 55)
    print("ЛАБОРАТОРНА РОБОТА №7 — МЕРЕЖА ФЕЙСТЕЛЯ")
    print("=" * 55)

    print(f"Варіант: {variant['variant']}")
    print(f"Початковий блок: L0={to_bits(L0)}, R0={to_bits(R0)}")
    print("Раундові ключі:", [to_bits(k) for k in keys])

    print("\nШИФРУВАННЯ:")
    L_enc, R_enc = feistel_encrypt_block(L0, R0, keys)

    print(f"\nЗашифрований блок: {to_bits(L_enc)}{to_bits(R_enc)}")

    print("\nДЕШИФРУВАННЯ:")
    L_dec, R_dec = feistel_decrypt_block(L_enc, R_enc, keys)

    print(f"Відновлений блок: L0={to_bits(L_dec)}, R0={to_bits(R_dec)}")

    success = (L_dec, R_dec) == (L0, R0)

    print("\nПЕРЕВІРКА:")
    print(f"Симетрія підтверджена: {success}")


if __name__ == "__main__":
    main()
