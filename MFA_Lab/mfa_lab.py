
import json
import time

from totp_mfa import totp, verify_totp


# Завантаження індивідуального варіанта
with open("variant_9.json", "r", encoding="utf-8") as file:
    variant = json.load(file)

secret = variant["secret_b32"]
digits = variant["digits"]
step = variant["step_seconds"]
drift = variant["drift_windows"]

print("=" * 60)
print("ЛАБОРАТОРНА РОБОТА №4")
print("Реалізація багатофакторної автентифікації TOTP")
print("=" * 60)

print("\nІНДИВІДУАЛЬНІ ПАРАМЕТРИ")
print(f"Варіант: {variant['variant']}")
print(f"Кількість цифр: {digits}")
print(f"Часовий крок: {step} секунд")
print(f"Допуск дрейфу: ±{drift} вікна")
print(f"AAA-протокол: {variant['aaa_protocol']}")
print(f"Сценарій: {variant['aaa_scenario']}")

# Крок 1. Генерація поточного TOTP
print("\n" + "=" * 60)
print("КРОК 1. ГЕНЕРАЦІЯ ПОТОЧНОГО TOTP")
print("=" * 60)

current_time = time.time()
current_code = totp(
    secret,
    timestamp=current_time,
    step=step,
    digits=digits
)

print(f"Поточний TOTP-код: {current_code}")
print(f"Час дії одного коду: {step} секунд")

# Крок 2. Перевірка правильного та неправильного коду
print("\n" + "=" * 60)
print("КРОК 2. ПЕРЕВІРКА TOTP")
print("=" * 60)

valid = verify_totp(
    secret,
    current_code,
    timestamp=current_time,
    step=step,
    digits=digits,
    drift_windows=drift
)

print(
    f"Правильний код {current_code}: "
    f"{'ПРИЙНЯТО' if valid else 'ВІДХИЛЕНО'}"
)

wrong_code = "0" * digits
if wrong_code == current_code:
    wrong_code = "1" * digits

invalid = verify_totp(
    secret,
    wrong_code,
    timestamp=current_time,
    step=step,
    digits=digits,
    drift_windows=drift
)

print(
    f"Неправильний код {wrong_code}: "
    f"{'ПРИЙНЯТО' if invalid else 'ВІДХИЛЕНО'}"
)

# Крок 3. Демонстрація часового дрейфу
print("\n" + "=" * 60)
print("КРОК 3. ДЕМОНСТРАЦІЯ TIME-DRIFT")
print("=" * 60)

# Визначаємо попереднє часове вікно
current_counter = int(current_time // step)
previous_timestamp = (current_counter - 1) * step + 1

past_code = totp(
    secret,
    timestamp=previous_timestamp,
    step=step,
    digits=digits
)

print(f"Код попереднього часового вікна: {past_code}")

# Перевірка без допуску дрейфу
without_drift = verify_totp(
    secret,
    past_code,
    timestamp=current_time,
    step=step,
    digits=digits,
    drift_windows=0
)

print(
    "Допуск drift_windows=0: "
    f"{'ПРИЙНЯТО' if without_drift else 'ВІДХИЛЕНО'}"
)

# Перевірка з індивідуальним допуском ±2
with_drift = verify_totp(
    secret,
    past_code,
    timestamp=current_time,
    step=step,
    digits=digits,
    drift_windows=drift
)

print(
    f"Допуск drift_windows={drift}: "
    f"{'ПРИЙНЯТО' if with_drift else 'ВІДХИЛЕНО'}"
)

# Крок 4. Розрахункові параметри MFA
print("\n" + "=" * 60)
print("КРОК 4. ІНДИВІДУАЛЬНІ ЙМОВІРНОСТІ")
print("=" * 60)

p_password = variant["p_password_compromise"]
p_second = variant["p_second_factor_compromise"]

print(f"Ймовірність компрометації пароля: {p_password}")
print(f"Ймовірність компрометації другого фактора: {p_second}")

print("\nПеревірку TOTP завершено.")
