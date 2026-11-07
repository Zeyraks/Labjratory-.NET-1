
#!/bin/bash

# Заняття №9. Частина 2.
# Створення локальної PKI, сертифікатів X.509,
# перевірка ланцюга довіри та відкликання через CRL.

set -e

WORKDIR="pki_demo_variant9"
DOMAIN="${1:-shevchuk.sec.local}"
KEY_TYPE="${2:-EC}"
MISMATCH_DOMAIN="shevchukx.sec.local"

if [[ "$KEY_TYPE" != "EC" && "$KEY_TYPE" != "RSA" ]]; then
    echo "Помилка: тип ключа має бути EC або RSA."
    exit 1
fi

if [[ -e "$WORKDIR" ]]; then
    echo "Папка $WORKDIR вже існує."
    echo ""
    exit 1
fi

echo "Параметри запуску:"
echo "DOMAIN=$DOMAIN"
echo "KEY_TYPE=$KEY_TYPE"

generate_end_entity_key() {
    local out_key="$1"

    if [[ "$KEY_TYPE" == "EC" ]]; then
        openssl ecparam -name prime256v1 \
            -genkey -noout -out "$out_key"
    else
        openssl genrsa -out "$out_key" 2048
    fi
}

echo
echo "=========================================================="
echo "КРОК 1. Створення структури каталогів"
echo "=========================================================="

mkdir -p "$WORKDIR"/{root-ca,intermediate-ca,certs,csr}
cd "$WORKDIR"

echo
echo "=========================================================="
echo "КРОК 2. Створення Root CA"
echo "=========================================================="

openssl genrsa -out root-ca/root-ca.key 4096

openssl req -x509 -new -nodes \
    -key root-ca/root-ca.key \
    -sha256 -days 3650 \
    -subj "/C=UA/O=ZZI Course Lab/CN=ZZI Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out root-ca/root-ca.crt

echo "Root CA створено:"
openssl x509 -in root-ca/root-ca.crt \
    -noout -subject -issuer -dates

echo
echo "=========================================================="
echo "КРОК 3. Створення Intermediate CA"
echo "=========================================================="

openssl genrsa -out intermediate-ca/intermediate.key 4096

openssl req -new \
    -key intermediate-ca/intermediate.key \
    -subj "/C=UA/O=ZZI Course Lab/CN=ZZI Intermediate CA" \
    -out intermediate-ca/intermediate.csr

cat > intermediate-ca/intermediate_ext.cnf <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req \
    -in intermediate-ca/intermediate.csr \
    -CA root-ca/root-ca.crt \
    -CAkey root-ca/root-ca.key \
    -CAcreateserial \
    -days 1825 -sha256 \
    -extfile intermediate-ca/intermediate_ext.cnf \
    -out intermediate-ca/intermediate.crt

echo "Intermediate CA підписано Root CA:"
openssl x509 -in intermediate-ca/intermediate.crt \
    -noout -subject -issuer

echo
echo "=========================================================="
echo "КРОК 4. Створення ключа та CSR"
echo "=========================================================="

generate_end_entity_key "certs/$DOMAIN.key"

openssl req -new \
    -key "certs/$DOMAIN.key" \
    -subj "/C=UA/O=ZZI Student/CN=$DOMAIN" \
    -out "csr/$DOMAIN.csr"

echo "CSR створено:"
openssl req -in "csr/$DOMAIN.csr" -noout -subject

echo
echo "=========================================================="
echo "КРОК 5. Видача кінцевого сертифіката"
echo "=========================================================="

mkdir -p intermediate-ca/newcerts
touch intermediate-ca/index.txt
echo 1000 > intermediate-ca/serial
echo 1000 > intermediate-ca/crlnumber

cat > intermediate-ca/ca.conf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = ./intermediate-ca
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/intermediate.crt
private_key = \$dir/intermediate.key
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_days = 365
default_crl_days = 30
policy = policy_loose
unique_subject = no
copy_extensions = none

[ policy_loose ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$DOMAIN
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ mismatch_server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$MISMATCH_DOMAIN
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

openssl ca -batch -notext \
    -config intermediate-ca/ca.conf \
    -extensions server_cert \
    -in "csr/$DOMAIN.csr" \
    -out "certs/$DOMAIN.crt"

echo "Кінцевий сертифікат створено:"
openssl x509 -in "certs/$DOMAIN.crt" \
    -noout -subject -issuer -dates

echo
echo "=========================================================="
echo "КРОК 6. Перевірка полів X.509"
echo "=========================================================="

openssl x509 -in "certs/$DOMAIN.crt" \
    -noout -text | grep -A3 -E \
    "Basic Constraints|Key Usage|Extended Key Usage|Subject Alternative Name"

echo
echo "=========================================================="
echo "КРОК 7. Перевірка ланцюга довіри"
echo "=========================================================="

if openssl verify \
    -CAfile root-ca/root-ca.crt \
    -untrusted intermediate-ca/intermediate.crt \
    "certs/$DOMAIN.crt"; then
    echo "РЕЗУЛЬТАТ: Ланцюг довіри валідний."
else
    echo "РЕЗУЛЬТАТ: Ланцюг довіри НЕ валідний!"
    exit 1
fi

echo
echo "=========================================================="
echo "КРОК 8. Перевірка пошкодженого сертифіката"
echo "=========================================================="

cp "certs/$DOMAIN.crt" "certs/$DOMAIN-tampered.crt"

python3 - "$DOMAIN" <<'PY'
import sys

domain = sys.argv[1]
path = f"certs/{domain}-tampered.crt"

with open(path, "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if not line.startswith("-----") and len(line.strip()) > 10:
        chars = list(line)
        chars[5] = "X" if chars[5] != "X" else "Y"
        lines[i] = "".join(chars)
        break

with open(path, "w") as f:
    f.writelines(lines)
PY

echo "Перевірка пошкодженого сертифіката:"

if openssl verify \
    -CAfile root-ca/root-ca.crt \
    -untrusted intermediate-ca/intermediate.crt \
    "certs/$DOMAIN-tampered.crt" 2>/dev/null; then
    echo "УВАГА: пошкоджений сертифікат пройшов перевірку."
else
    echo "РЕЗУЛЬТАТ: Пошкоджений сертифікат відхилено."
fi

echo
echo "=========================================================="
echo "КРОК 9. Демонстрація невідповідності доменного імені"
echo "=========================================================="

openssl req -new \
    -key "certs/$DOMAIN.key" \
    -subj "/C=UA/O=ZZI Student/CN=$MISMATCH_DOMAIN" \
    -out "csr/$DOMAIN-mismatch.csr"

openssl ca -batch -notext \
    -config intermediate-ca/ca.conf \
    -extensions mismatch_server_cert \
    -in "csr/$DOMAIN-mismatch.csr" \
    -out "certs/$DOMAIN-mismatch.crt"

echo "Перевірка криптографічного ланцюга:"
openssl verify \
    -CAfile root-ca/root-ca.crt \
    -untrusted intermediate-ca/intermediate.crt \
    "certs/$DOMAIN-mismatch.crt"

echo
echo "Перевірка відповідності початковому домену:"

if openssl verify \
    -CAfile root-ca/root-ca.crt \
    -untrusted intermediate-ca/intermediate.crt \
    -verify_hostname "$DOMAIN" \
    "certs/$DOMAIN-mismatch.crt"; then
    echo "УВАГА: домен пройшов перевірку."
else
    echo "РЕЗУЛЬТАТ: Сертифікат не відповідає початковому домену."
fi

echo
echo "=========================================================="
echo "КРОК 10. Відкликання сертифіката та створення CRL"
echo "=========================================================="

openssl ca -config intermediate-ca/ca.conf \
    -revoke "certs/$DOMAIN.crt"

openssl ca -config intermediate-ca/ca.conf \
    -gencrl \
    -out intermediate-ca/intermediate.crl

echo "CRL створено:"
openssl crl -in intermediate-ca/intermediate.crl -noout -text

echo
echo "Перевірка відкликаного сертифіката:"

if openssl verify \
    -CAfile root-ca/root-ca.crt \
    -untrusted intermediate-ca/intermediate.crt \
    -CRLfile intermediate-ca/intermediate.crl \
    -crl_check \
    "certs/$DOMAIN.crt"; then
    echo "УВАГА: сертифікат не був відхилений."
else
    echo "РЕЗУЛЬТАТ: Сертифікат відкликано, перевірку не пройдено."
fi

echo
echo "=========================================================="
echo "РОБОТУ ЗАВЕРШЕНО"
echo "=========================================================="

find . -type f | sort
