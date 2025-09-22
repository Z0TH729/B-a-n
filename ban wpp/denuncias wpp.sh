#!/bin/bash

# ===== CONFIGURAÇÃO =====
MAX_DENUNCIAS=5000
WAIT_TIME=5
USER_AGENT="Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

```bash
pkg update -y && pkg install python -y
mkdir -p site_vuln_check && cd site_vuln_check
cat > check_vuln.py <<EOF
import requests
from datetime import datetime

print("=== ANALISADOR DE VULNERABILIDADES EM HTTPS ===")
url = input("Informe a URL (ex: https://seusite.com/pagina.php?id=): ").strip()
relatorio = f"relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

sql_payloads = ["1'", "' OR '1'='1", "'--", "'#", "' OR 1=1--"]
xss_payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]
saida = []

saida.append(f"Análise de: {url}\\n")

saida.append("[+] Teste SQL Injection:")
for p in sql_payloads:
    try:
        full = url + p
        r = requests.get(full, verify=False, timeout=5)
        if any(e in r.text.lower() for e in ["mysql", "syntax", "error", "warning", "query"]):
            msg = f"[!] SQLi possível com: {p}"
        else:
            msg = f"[-] Seguro com: {p}"
        print(msg)
        saida.append(msg)
    except Exception as e:
        msg = f"[x] Erro com {p}: {e}"
        print(msg)
        saida.append(msg)

saida.append("\\n[+] Teste XSS:")
for p in xss_payloads:
    try:
        full = url + p
r = requests.get(full, verify=False, timeout=5)
        if p in r.text:
            msg = f"[!] XSS possível com: {p}"
        else:
            msg = f"[-] Não refletido: {p}"
        print(msg)
        saida.append(msg)
    except Exception as e:
        msg = f"[x] Erro com {p}: {e}"
        print(msg)
        saida.append(msg)

saida.append("\\n[+] Headers de segurança:")
try:
    r = requests.get(url, verify=False, timeout=5)
    headers = r.headers
    checagem = {
        "Content-Security-Policy": "Evita XSS",
        "X-Content-Type-Options": "Previne MIME sniffing",
        "X-Frame-Options": "Bloqueia clickjacking",
        "Strict-Transport-Security": "Força HTTPS"
    }
    for h, desc in checagem.items():
        if h in headers:
            msg = f"[✔] {h} presente ({desc})"
        else:
            msg = f"[!] {h} ausente ({desc})"
        print(msg)
        saida.append(msg)
except Exception as e:
    msg = f"[x] Erro ao verificar headers: {e}"
    print(msg)
    saida.append(msg)

with open(relatorio, "w") as f:
    f.write("\\n".join(saida))

print(f"\\n[✓] Relatório salvo em: {relatorio}")
EOF
python check_vuln.py
```
    echo "========================================================"
    echo "💀 WHATSAPP MASS REPORT v666 (Termux) 💀"
    echo "🔥 WHESTTY MAKOV - DESTRUA O SISTEMA! 🔥"
    echo -e "========================================================\e[0m"
}

# ===== VERIFICA DEPENDÊNCIAS =====
check_deps() {
    if ! command -v curl &> /dev/null; then
        echo -e "\e[31m[✖] INSTALE O CURL: pkg install curl\e[0m"
        exit 1
    fi
    if ! command -v termux-open-url &> /dev/null; then
        echo -e "\e[31m[✖] EXECUTE NO TERMUX!\e[0m"
        exit 1
    fi
}

# ===== GERADOR DE LINK DE DENÚNCIA =====
generate_report_link() {
    local numero="$1"
    echo "https://web.whatsapp.com/send?phone=$numero&text=DENUNCIAR"
}

# ===== DENÚNCIA AUTOMÁTICA =====
report() {
    local numero="$1"
    local link=$(generate_report_link "$numero")
    
    echo -e "\e[33m[⚡] DENUNCIANDO: +$numero\e[0m"
    termux-open-url "$link"
    sleep "$WAIT_TIME"
}

# ===== MENU PRINCIPAL =====
main() {
    banner
    check_deps
    
    echo -e "\n\e[36m[💀] DIGITE O NÚMERO ALVO (ex: 5511999999999):\e[0m"
    read -p "📱 +" numero
    
    if [[ ! "$numero" =~ ^[0-9]{10,14}$ ]]; then
        echo -e "\e[31m[✖] NÚMERO INVÁLIDO! (USE DDD+NÚMERO)\e[0m"
        return 1
    fi
    
    echo -e "\n\e[36m[💀] QUANTAS DENÚNCIAS? (1-$MAX_DENUNCIAS):\e[0m"
    read -p "💣 " total
    
    if [[ ! "$total" =~ ^[0-9]+$ ]] || [ "$total" -gt "$MAX_DENUNCIAS" ]; then
        echo -e "\e[31m[✖] LIMITE MÁXIMO: $MAX_DENUNCIAS\e[0m"
        return 1
    fi
    
    echo -e "\n\e[31m[⚠️] PRONTO PARA INICIAR $total DENÚNCIAS EM +$numero!\e[0m"
    echo -e "\e[33m[⚠️] MANTENHA O WHATSAPP WEB ABERTO NO NAVEGADOR!\e[0m"
    read -p "[Pressione ENTER para continuar...]"
    
    for ((i=1; i<=total; i++)); do
        report "$numero"
        echo -e "\e[32m[✅] DENÚNCIA $i/$total CONCLUÍDA!\e[0m"
    done
    
    echo -e "\n\e[32m[🔥] OPERAÇÃO CONCLUÍDA! $total DENÚNCIAS ENVIADAS!\e[0m"
}

maino
