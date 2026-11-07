
import json
import random
import sys

ALL_LEGIT_DOMAINS = [
    "google.com", "microsoft.com", "apple.com",
    "privatbank.ua", "monobank.ua", "facebook.com",
    "amazon.com", "github.com", "wikipedia.org",
    "youtube.com", "netflix.com", "dropbox.com",
    "instagram.com", "linkedin.com", "oschadbank.ua",
    "ukrposhta.ua"
]

ALL_PHISHING_PATTERNS = [
    ("tld-swap", lambda b, r: f"http://{b}-secure-login.tk/verify"),
    ("subdomain-trick", lambda b, r: f"http://{b}.accountverify.ru/signin?user=1"),
    ("ip-instead-of-domain", lambda b, r: f"http://{r.randint(1,254)}.{r.randint(1,254)}.{r.randint(1,254)}.{r.randint(1,254)}/{b}/login"),
    ("typosquatting", lambda b, r: f"http://{b.replace('o','0').replace('l','1')}.com/webapps/signin"),
    ("at-symbol-trick", lambda b, r: f"https://secure-{b}update.xyz/account@confirm"),
    ("support-subdomain", lambda b, r: f"http://{b}.{b}-support.info/resetpassword"),
    ("url-shortener", lambda b, r: f"http://bit.ly/{b[:3]}{r.randint(1000,9999)}"),
    ("double-brand", lambda b, r: f"http://{b}-{b}.tk/login.php?redirect={b}.com"),
    ("hyphen-flood", lambda b, r: f"http://{b}-account-security-check-verify.com/login"),
    ("homoglyph-like", lambda b, r: f"http://{b.replace('a','а')}.com/signin")
]

SCENARIO_PROFILES = [
    "Банківський сектор (фішинг під платіжні системи)",
    "Корпоративна пошта (фішинг під ІТ-відділ / HR)",
    "Соціальні мережі (фішинг під підтвердження акаунта)",
    "E-commerce (фішинг під підтвердження замовлення)",
    "Хмарні сервіси (фішинг під запит доступу до документа)"
]


def generate_variant(n):
    if not 1 <= n <= 30:
        raise ValueError("Номер варіанта має бути від 1 до 30")

    rng = random.Random(n)

    scenario = SCENARIO_PROFILES[n % 5]

    target_domains = rng.sample(
        ALL_LEGIT_DOMAINS, k=rng.randint(5, 7)
    )

    chosen_patterns = rng.sample(
        ALL_PHISHING_PATTERNS, k=rng.randint(4, 6)
    )

    total_examples = 150
    phish_ratio = round(rng.uniform(0.35, 0.65), 2)
    n_phish = int(total_examples * phish_ratio)
    n_legit = total_examples - n_phish

    legit_paths = [
        "/login", "/account", "/dashboard", "/signin",
        "/settings", "/", "/help", "/profile"
    ]

    data = []

    for _ in range(n_legit):
        domain = rng.choice(target_domains)
        path = rng.choice(legit_paths)

        data.append({
            "url": f"https://www.{domain}{path}",
            "label": 0
        })

    for _ in range(n_phish):
        brand = rng.choice(target_domains).split(".")[0]
        pattern_name, pattern_fn = rng.choice(chosen_patterns)
        url = pattern_fn(brand, rng)

        data.append({
            "url": url,
            "label": 1,
            "pattern": pattern_name
        })

    rng.shuffle(data)

    return {
        "variant": n,
        "scenario_profile": scenario,
        "target_domains": target_domains,
        "phishing_patterns_used": [
            p[0] for p in chosen_patterns
        ],
        "phish_ratio": phish_ratio,
        "total_examples": total_examples,
        "examples": data
    }


def main():
    if len(sys.argv) != 2:
        print("Використання: python3 variant_generator.py <номер>")
        sys.exit(1)

    n = int(sys.argv[1])
    variant = generate_variant(n)

    dataset_path = f"dataset_{n}.json"
    meta_path = f"variant_{n}_info.json"

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(
            variant["examples"], f,
            ensure_ascii=False, indent=2
        )

    meta = {
        k: v for k, v in variant.items()
        if k != "examples"
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"Варіант №{n}")
    print(f"Сценарій: {variant['scenario_profile']}")
    print(f"Домени: {', '.join(variant['target_domains'])}")
    print(f"Шаблони: {', '.join(variant['phishing_patterns_used'])}")
    print(f"Фішинг: {phish_ratio_percent(variant['phish_ratio'])}")
    print(f"Усього прикладів: {variant['total_examples']}")
    print(f"Створено файли: {dataset_path}, {meta_path}")


def phish_ratio_percent(ratio):
    return f"{ratio:.0%} / {1-ratio:.0%}"


if __name__ == "__main__":
    main()
