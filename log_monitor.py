import time
from collections import deque
import re
import json
import pandas as pd
from datetime import datetime, timedelta

# --- Configurações ---
LOG_FILE_PATH = 'access.log'
MAX_REQUESTS = 100
TIME_WINDOW = timedelta(seconds=10)
# Lista de IPs já alertados para não repetir o alerta
alerted_ips = set()

# Regex para extrair o IP de uma linha de log comum do Apache/Nginx
log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*')

# Dicionário para armazenar timestamps de requisições por IP
# A estrutura será: {'ip_address': deque([timestamp1, timestamp2, ...])}
ip_requests = {}

def generate_reports(ip_data):
    """Gera relatórios em JSON e HTML com os IPs mais ativos."""
    print("\n[RELATÓRIO] Gerando relatórios de atividade...")

    # Prepara os dados para o relatório
    report_data = []
    for ip, timestamps in ip_data.items():
        report_data.append({'IP': ip, 'RequestCount': len(timestamps)})

    if not report_data:
        print("[RELATÓRIO] Nenhum dado para gerar relatório.")
        return

    # Cria um DataFrame do Pandas para facilitar a manipulação
    df = pd.DataFrame(report_data)
    df = df.sort_values(by='RequestCount', ascending=False)

    # Gera relatório JSON
    json_report = df.to_json(orient='records', indent=4)
    with open('report.json', 'w') as f:
        f.write(json_report)
    print("[RELATÓRIO] Relatório JSON salvo em 'report.json'")

    # Gera relatório HTML
    html_report = df.to_html(index=False)
    with open('report.html', 'w') as f:
        f.write("<h1>Relatório de Atividade de IPs</h1>")
        f.write(html_report)
    print("[RELATÓRIO] Relatório HTML salvo em 'report.html'")


def monitor_log_file(filepath):
    """Monitora um arquivo de log em tempo real (simulação)."""
    print(f"[*] Monitorando o arquivo de log: {filepath}")
    print(f"[*] Regra: Alerta se > {MAX_REQUESTS} requisições em {TIME_WINDOW.seconds} segundos.")

    try:
        with open(filepath, 'r') as f:
            # Move o cursor para o final do arquivo
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1) # Espera por novas linhas
                    continue

                match = log_pattern.match(line)
                if match:
                    ip = match.group(1)
                    current_time = datetime.now()

                    # Se o IP não está no nosso dicionário, inicializa com um deque
                    if ip not in ip_requests:
                        ip_requests[ip] = deque()

                    # Adiciona o timestamp da requisição atual
                    ip_requests[ip].append(current_time)

                    # Remove timestamps antigos que estão fora da janela de tempo
                    while ip_requests[ip] and (current_time - ip_requests[ip][0]) > TIME_WINDOW:
                        ip_requests[ip].popleft()

                    # Verifica se o número de requisições excede o limite
                    if len(ip_requests[ip]) > MAX_REQUESTS:
                        if ip not in alerted_ips:
                            print(f"[!!!] ALERTA DE POSSÍVEL ATAQUE DDOS [!!!]")
                            print(f"    -> IP: {ip}")
                            print(f"    -> Requisições: {len(ip_requests[ip])} em {TIME_WINDOW.seconds} segundos.")
                            # Ação de bloqueio (simulada)
                            block_ip(ip)
                            alerted_ips.add(ip)

    except KeyboardInterrupt:
        print("\n[INFO] Monitoramento interrompido pelo usuário.")
        generate_reports(ip_requests)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de log não encontrado em: {filepath}")


def block_ip(ip_address):
    """
    Função para simular o bloqueio de um IP.
    No Windows, o comando real seria mais complexo (`netsh advfirewall ...`).
    Para este trabalho, a simulação é mais segura e suficiente.
    """
    print(f"[AÇÃO] SIMULANDO bloqueio do IP {ip_address} no firewall.")
    # Em um sistema Linux real, você poderia usar:
    # os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
    # No Windows, seria algo como:
    # subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', ...])


if __name__ == "__main__":
    monitor_log_file(LOG_FILE_PATH)