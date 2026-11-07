
import json
import re
import sys
import numpy as np

from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# Ознаки URL
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    return {
        "url_length": len(url),
        "dots": url.count("."),
        "hyphens": url.count("-"),
        "digits": sum(c.isdigit() for c in url),
        "domain_digits": sum(c.isdigit() for c in domain),
        "at_symbol": int("@" in url),
        "https": int(parsed.scheme == "https"),
        "ip_address": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))),
        "subdomains": max(0, len(domain.split(".")) - 2),
        "suspicious_words": sum(
            word in url.lower()
            for word in ["login", "verify", "secure", "account", "update"]
        )
    }


def load_dataset(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def prepare_data(data):
    X = []
    y = []

    for item in data:
        X.append(extract_features(item["url"]))
        y.append(item["label"])

    feature_names = list(X[0].keys())

    X = np.array([
        [features[name] for name in feature_names]
        for features in X
    ])

    return X, np.array(y), feature_names


def train_and_evaluate(X, y, feature_names):
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n========== РЕЗУЛЬТАТИ МОДЕЛІ ==========")
    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1-score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

    print("\nМатриця плутанини:")
    print(confusion_matrix(y_test, predictions))

    print("\nДетальний звіт:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    ))

    print("\nВаги ознак:")
    for name, importance in sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{name}: {importance:.4f}")

    return model


def main():
    if len(sys.argv) != 2:
        print("Використання: python3 phishing_detector.py dataset_9.json")
        return

    filename = sys.argv[1]

    data = load_dataset(filename)

    print(f"Завантажено прикладів: {len(data)}")

    X, y, feature_names = prepare_data(data)

    print(f"Кількість ознак: {len(feature_names)}")
    print(f"Легітимні URL: {sum(y == 0)}")
    print(f"Фішингові URL: {sum(y == 1)}")

    train_and_evaluate(X, y, feature_names)


if __name__ == "__main__":
    main()
