
import hmac
import hashlib
import base64
import struct
import time
import secrets


def generate_secret(num_bytes: int = 20) -> str:
    """Генерує криптографічно стійкий секретний ключ Base32."""
    random_bytes = secrets.token_bytes(num_bytes)
    return base64.b32encode(random_bytes).decode("utf-8")


def hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """Обчислює HOTP за RFC 4226."""
    key = base64.b32decode(secret_b32, casefold=True)
    counter_bytes = struct.pack(">Q", counter)

    hmac_hash = hmac.new(
        key,
        counter_bytes,
        hashlib.sha1
    ).digest()

    offset = hmac_hash[-1] & 0x0F
    truncated = hmac_hash[offset:offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF

    return str(code_int % (10 ** digits)).zfill(digits)


def totp(
    secret_b32: str,
    timestamp: float = None,
    t0: int = 0,
    step: int = 30,
    digits: int = 6
) -> str:
    """Обчислює TOTP за RFC 6238."""
    if timestamp is None:
        timestamp = time.time()

    counter = int((timestamp - t0) // step)
    return hotp(secret_b32, counter, digits)


def verify_totp(
    secret_b32: str,
    user_code: str,
    timestamp: float = None,
    t0: int = 0,
    step: int = 30,
    digits: int = 6,
    drift_windows: int = 1
) -> bool:
    """Перевіряє TOTP з урахуванням допустимого часового дрейфу."""
    if timestamp is None:
        timestamp = time.time()

    current_counter = int((timestamp - t0) // step)

    for delta in range(-drift_windows, drift_windows + 1):
        candidate_counter = current_counter + delta

        if candidate_counter < 0:
            continue

        if hotp(secret_b32, candidate_counter, digits) == user_code:
            return True

    return False


def build_provisioning_uri(
    secret_b32: str,
    account_name: str,
    issuer: str,
    digits: int = 6,
    step: int = 30
) -> str:
    """Формує URI для налаштування застосунку-аутентифікатора."""
    return (
        f"otpauth://totp/{issuer}:{account_name}"
        f"?secret={secret_b32}&issuer={issuer}"
        f"&algorithm=SHA1&digits={digits}&period={step}"
    )


if __name__ == "__main__":
    secret = generate_secret()
    code = totp(secret)

    print("Демонстрація TOTP")
    print("Секрет:", secret)
    print("Код:", code)
    print("Перевірка:", verify_totp(secret, code))
