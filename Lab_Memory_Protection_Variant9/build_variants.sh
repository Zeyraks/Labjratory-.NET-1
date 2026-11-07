
#!/bin/bash

# Збірки для дослідження механізмів захисту пам'яті:
# NX, Stack Canaries та PIE/ASLR.

set -e

mkdir -p builds

echo
echo "=========================================================="
echo "Варіант 1: NX, без Stack Canary та PIE"
echo "=========================================================="

gcc -O0 -Wall -Wextra -o builds/vuln_unprotected vulnerable.c \
    -fno-stack-protector \
    -z noexecstack \
    -no-pie

echo "Скомпільовано: builds/vuln_unprotected"

echo
echo "=========================================================="
echo "Варіант 2: NX + PIE, без Stack Canary"
echo "=========================================================="

gcc -O0 -Wall -Wextra -o builds/vuln_nx_only vulnerable.c \
    -fno-stack-protector \
    -z noexecstack \
    -fPIE -pie

echo "Скомпільовано: builds/vuln_nx_only"

echo
echo "=========================================================="
echo "Варіант 3: NX + Stack Canary, без PIE"
echo "=========================================================="

gcc -O0 -Wall -Wextra -o builds/vuln_canary vulnerable.c \
    -fstack-protector-all \
    -z noexecstack \
    -no-pie

echo "Скомпільовано: builds/vuln_canary"

echo
echo "=========================================================="
echo "Варіант 4: ПОВНИЙ ЗАХИСТ — NX + Canary + PIE"
echo "=========================================================="

gcc -O0 -Wall -Wextra -o builds/vuln_full_protection vulnerable.c \
    -fstack-protector-all \
    -z noexecstack \
    -fPIE -pie

echo "Скомпільовано: builds/vuln_full_protection"

echo
echo "=========================================================="
echo "Перевірка застосованих механізмів захисту"
echo "=========================================================="

for binary in \
    builds/vuln_unprotected \
    builds/vuln_nx_only \
    builds/vuln_canary \
    builds/vuln_full_protection
do
    echo
    echo "--- $binary ---"

    echo -n "NX (стек не виконується): "
    if readelf -W -l "$binary" | grep GNU_STACK | grep -q 'RWE'; then
        echo "НЕ УВІМКНЕНО"
    else
        echo "УВІМКНЕНО (виконуваний стек не позначений)"
    fi

    echo -n "PIE: "
    if readelf -h "$binary" | grep -q 'Type:.*DYN'; then
        echo "УВІМКНЕНО"
    else
        echo "ВИМКНЕНО"
    fi

    echo -n "Stack Canary: "
    if objdump -d "$binary" | grep -q '__stack_chk_fail'; then
        echo "УВІМКНЕНО"
    else
        echo "ВИМКНЕНО"
    fi
done

echo
echo "Перевірку завершено."
