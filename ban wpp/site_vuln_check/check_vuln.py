import requests
from datetime import datetime

print("=== ANALISADOR DE VULNERABILIDADES EM HTTPS ===")
url = input("Informe a URL (ex: https://seusite.com/pagina.php?id=): ").strip()
relatorio = f"relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

sql_payloads = ["1'", "' OR '1'='1", "'--", "'#", "' OR 1=1--"]
xss_payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]
saida = []

saida.append(f"Análise de: {url}\n")

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

saida.append("\n[+] Teste XSS:")
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

saida.append("\n[+] Headers de segurança:")
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
    f.write("\n".join(saida))

print(f"\n[✓] Relatório salvo em: {relatorio}")
