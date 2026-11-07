
# ---------------------------------------------------------------------
# Лабораторна робота №6
# Потокові шифри та генератори псевдовипадкових чисел
# LFSR, Berlekamp-Massey, RC4, статистичні тести
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# ЧАСТИНА 1. LFSR
# ---------------------------------------------------------------------

class LFSR:
    """
    LFSR довжини L з генераторним поліномом,
    заданим вектором відводів taps.

    Індекси taps: 0-based від молодшого біта s0.
    """

    def __init__(self, seed: list[int], taps: list[int]):
        if not seed:
            raise ValueError("Початковий стан не може бути порожнім")

        if not any(seed):
            raise ValueError("Початковий стан не може бути всіма нулями")

        if any(bit not in (0, 1) for bit in seed):
            raise ValueError("Стан регістра повинен містити лише біти 0 і 1")

        if any(tap < 0 or tap >= len(seed) for tap in taps):
            raise ValueError("Індекс відводу виходить за межі регістра")

        self.state = list(seed)
        self.taps = list(taps)
        self.length = len(seed)

    def step(self) -> int:
        """Виконує один такт роботи регістра."""

        feedback = 0

        for tap in self.taps:
            feedback ^= self.state[tap]

        output_bit = self.state[0]
        self.state = self.state[1:] + [feedback]

        return output_bit

    def generate(self, n_bits: int) -> list[int]:
        """Генерує задану кількість бітів."""

        if n_bits < 0:
            raise ValueError("Кількість бітів не може бути від'ємною")

        return [self.step() for _ in range(n_bits)]


def lfsr_period(
    seed: list[int],
    taps: list[int],
    max_steps: int = 100_000
) -> int:
    """Визначає період LFSR за повторенням початкового стану."""

    lfsr = LFSR(seed, taps)
    initial_state = tuple(seed)

    for step in range(1, max_steps + 1):
        lfsr.step()

        if tuple(lfsr.state) == initial_state:
            return step

    return -1


# ---------------------------------------------------------------------
# ЧАСТИНА 2. АЛГОРИТМ БЕРЛЕКЕМПА-МЕССІ
# ---------------------------------------------------------------------

def berlekemp_massey(bits: list[int]) -> tuple[int, list[int]]:
    """
    Відновлює найкоротший LFSR за відомою бітовою послідовністю.

    Повертає:
    L — довжину регістра;
    taps — індекси відводів у нотації цього модуля.
    """

    n = len(bits)

    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("Послідовність повинна містити лише 0 і 1")

    C = [1] + [0] * n
    B = [1] + [0] * n

    L = 0
    m = 1

    for i in range(n):
        d = bits[i]

        for j in range(1, L + 1):
            d ^= C[j] & bits[i - j]

        if d == 0:
            m += 1

        elif 2 * L <= i:
            T = C.copy()

            for j in range(len(B)):
                if j + m < len(C):
                    C[j + m] ^= B[j]

            L = i + 1 - L
            B = T
            m = 1

        else:
            for j in range(len(B)):
                if j + m < len(C):
                    C[j + m] ^= B[j]

            m += 1

    poly_indices_j = [
        j for j in range(1, L + 1)
        if C[j] == 1
    ]

    state_taps = sorted(L - j for j in poly_indices_j)

    return L, state_taps


# ---------------------------------------------------------------------
# ЧАСТИНА 3. RC4 (KSA + PRGA)
# ---------------------------------------------------------------------

class RC4:
    """Навчальна реалізація потокового шифру RC4."""

    def __init__(self, key: bytes):
        if not key:
            raise ValueError("Ключ RC4 не може бути порожнім")

        self.S = self._ksa(key)
        self.i = 0
        self.j = 0

    @staticmethod
    def _ksa(key: bytes) -> list[int]:
        """Key Scheduling Algorithm."""

        S = list(range(256))
        j = 0
        L = len(key)

        for i in range(256):
            j = (j + S[i] + key[i % L]) % 256
            S[i], S[j] = S[j], S[i]

        return S

    def _prga_byte(self) -> int:
        """Pseudo-Random Generation Algorithm."""

        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256

        self.S[self.i], self.S[self.j] = (
            self.S[self.j],
            self.S[self.i]
        )

        t = (self.S[self.i] + self.S[self.j]) % 256

        return self.S[t]

    def keystream(self, n_bytes: int) -> bytes:
        """Генерує гаму заданої довжини в байтах."""

        if n_bytes < 0:
            raise ValueError("Кількість байтів не може бути від'ємною")

        return bytes(self._prga_byte() for _ in range(n_bytes))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Шифрує відкритий текст."""

        keystream = self.keystream(len(plaintext))

        return bytes(
            p ^ k for p, k in zip(plaintext, keystream)
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Розшифровує шифротекст."""

        return self.encrypt(ciphertext)


# ---------------------------------------------------------------------
# ЧАСТИНА 4. СТАТИСТИЧНІ ТЕСТИ
# ---------------------------------------------------------------------

def frequency_test(bits: list[int]) -> dict:
    """Частотний тест — перевірка кількості нулів та одиниць."""

    n = len(bits)

    if n == 0:
        raise ValueError("Послідовність не може бути порожньою")

    ones = sum(bits)
    zeros = n - ones
    proportion = ones / n

    return {
        "test": "Частотний (моно-бітний)",
        "ones": ones,
        "zeros": zeros,
        "n": n,
        "proportion_ones": round(proportion, 4),
        "passed": abs(proportion - 0.5) < 0.02
    }


def runs_test(bits: list[int]) -> dict:
    """Тест серій — підрахунок довжин однакових бітів."""

    if not bits:
        raise ValueError("Послідовність не може бути порожньою")

    runs = []
    current_run = 1

    for i in range(1, len(bits)):
        if bits[i] == bits[i - 1]:
            current_run += 1
        else:
            runs.append(current_run)
            current_run = 1

    runs.append(current_run)

    total_runs = len(runs)
    length_distribution = {}

    for run_length in runs:
        length_distribution[run_length] = (
            length_distribution.get(run_length, 0) + 1
        )

    return {
        "test": "Розподіл серій (Runs)",
        "total_runs": total_runs,
        "length_distribution": dict(
            sorted(length_distribution.items())
        ),
        "expected_ratio_length_1": 0.5,
        "actual_ratio_length_1": round(
            length_distribution.get(1, 0) / total_runs, 4
        )
    }


# ---------------------------------------------------------------------
# ДОПОМІЖНА ФУНКЦІЯ
# ---------------------------------------------------------------------

def bits_to_str(bits: list[int]) -> str:
    """Перетворює список бітів у рядок."""

    return "".join(str(bit) for bit in bits)
