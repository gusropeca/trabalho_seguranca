# Importações necessárias para todo o programa
import time
import re
import json
import pandas as pd
from collections import deque
from datetime import datetime, timedelta
from scapy.all import IP, sniff
from scapy.arch.windows import get_windows_if_list 
from collections import deque
import threading

# --- Configurações Globais ---
# Configs para o monitor de LOGS
LOG_FILE_PATH = 'access.log'
LOG_MAX_REQUESTS = 20
LOG_TIME_WINDOW = timedelta(seconds=60)

# Configs para o sniffer de PACOTES
PACKET_MAX_COUNT = 100
PACKET_TIME_WINDOW = timedelta(seconds=10)

# --- Estruturas de Dados Compartilhadas ---
detected_malicious_ips = set()
ip_lock = threading.Lock()
# Dicionário para guardar o histórico completo para os relatórios
ip_history_for_report = {}

def run_log_monitor():
    """Função que monitora o arquivo de log em sua própria thread."""
    print("[LOG_MONITOR] Iniciando monitoramento de logs...")
    ip_requests = {}
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*')

    try:
        # Garante que o arquivo de log exista antes de começar
        open(LOG_FILE_PATH, 'a').close()
        
        with open(LOG_FILE_PATH, 'r') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                match = log_pattern.match(line)
                if match:
                    ip = match.group(1)
                      # ----> ADICIONE ESTAS 3 LINHAS <----
                    with ip_lock:
                        ip_history_for_report[ip] = ip_history_for_report.get(ip, 0) + 1
                # ------------------------------------
                    current_time = datetime.now()

                    if ip not in ip_requests:
                        ip_requests[ip] = deque()
                    
                    ip_requests[ip].append(current_time)

                    while ip_requests[ip] and (current_time - ip_requests[ip][0]) > LOG_TIME_WINDOW:
                        ip_requests[ip].popleft()

                    if len(ip_requests[ip]) > LOG_MAX_REQUESTS:
                        # Pega o "bastão da palavra" para escrever no "mural"
                        with ip_lock:
                            if ip not in detected_malicious_ips:
                                print(f"\n[!!!] ALERTA DE LOG: Atividade suspeita do IP {ip} [!!!]")
                                detected_malicious_ips.add(ip)

    except Exception as e:
        print(f"[LOG_MONITOR] ERRO: {e}")
        
        
def run_packet_sniffer():
    """Função que captura pacotes de rede em sua própria thread."""
    from scapy.all import get_working_if # Importa a função de detecção automática

    print("[PACKET_SNIFFER] Iniciando captura de pacotes (requer admin)...")
    
    active_interface = None
    try:
        # TENTATIVA 1: Modo Automático
        #active_interface_obj = get_working_if()
        active_interface = active_interface_obj.name
        print(f"[PACKET_SNIFFER] Interface de rede ativa detectada automaticamente: {active_interface}")
    except Exception:
        # TENTATIVA 2: Modo Interativo (Plano B)
        print("[PACKET_SNIFFER] Não foi possível detectar a interface automaticamente.")
        print("[PACKET_SNIFFER] Por favor, selecione a interface de rede para monitorar:")
        
        interfaces = get_windows_if_list()
        
        for i, iface in enumerate(interfaces):
            print(f"  {i}: {iface.get('name')} ({iface.get('description')})")

        while active_interface is None:
            try:
                choice = input("--> Digite o NÚMERO da interface desejada e pressione Enter: ")
                chosen_interface_details = interfaces[int(choice)]
                active_interface = chosen_interface_details.get('name')
            except (ValueError, IndexError):
                print("Escolha inválida. Por favor, digite um dos números da lista.")

    print(f"[PACKET_SNIFFER] Ótimo! Ouvindo na interface: {active_interface}")

    packet_counts = {}

    def process_packet(packet):
        if IP in packet:
            ip_src = packet[IP].src
            current_time = datetime.now()

            if ip_src not in packet_counts:
                packet_counts[ip_src] = deque()
            
            packet_counts[ip_src].append(current_time)

            while packet_counts[ip_src] and (current_time - packet_counts[ip_src][0]) > PACKET_TIME_WINDOW:
                packet_counts[ip_src].popleft()

            if len(packet_counts[ip_src]) > PACKET_MAX_COUNT:
                with ip_lock:
                    if ip_src not in detected_malicious_ips:
                        print(f"\n[!!!] ALERTA DE PACOTE: Tráfego excessivo do IP {ip_src} [!!!]")
                        detected_malicious_ips.add(ip_src)
    try:
        sniff(iface=active_interface, prn=process_packet, store=False, stop_filter=lambda p: stop_event.is_set())
    except Exception as e:
        print(f"[PACKET_SNIFFER] ERRO: Certifique-se de rodar como admin. Detalhes: {e}")
        
        
        
def generate_reports():
    """Gera relatórios em HTML e JSON com os IPs mais ativos."""
    print("\n[RELATÓRIO] Gerando relatórios de atividade...")
    report_data = []
    with ip_lock:
        if not ip_history_for_report:
            print("[RELATÓRIO] Nenhum dado para gerar relatório.")
            return

        for ip, count in ip_history_for_report.items():
            report_data.append({'IP': ip, 'TotalRequests': count})

    df = pd.DataFrame(report_data).sort_values(by='TotalRequests', ascending=False)

    # Gera relatório JSON
    df.to_json('report.json', orient='records', indent=4)
    print("[RELATório] Relatório JSON salvo em 'report.json'")

    # Gera relatório HTML
    df.to_html('report.html', index=False, border=1)
    print("[RELATÓRIO] Relatório HTML salvo em 'report.html'")       


if __name__ == "__main__":
    print("--- Detector de DDoS Unificado ---")
    
    # Evento para sinalizar o encerramento das threads
    stop_event = threading.Event()

    # 1. Criar os "trabalhadores" (threads)
    log_thread = threading.Thread(target=run_log_monitor)
    sniffer_thread = threading.Thread(target=run_packet_sniffer)

    # 2. Definir como 'daemon' para que fechem com o programa principal
    log_thread.daemon = True
    sniffer_thread.daemon = True

    # 3. Iniciar o trabalho
    log_thread.start()
    sniffer_thread.start()

    # 4. Loop do "gerente": supervisiona e age
    blocked_ips = set()
    try:
        while True:
            # Pega o "bastão" para LER o mural com segurança
            with ip_lock:
                # Pega a lista de IPs que foram detectados mas ainda não foram bloqueados
                ips_to_block = detected_malicious_ips - blocked_ips
            
            for ip in ips_to_block:
                print(f"--- [AÇÃO CENTRAL] SIMULANDO bloqueio do IP {ip} no firewall. ---")
                blocked_ips.add(ip)

            time.sleep(10)


    except KeyboardInterrupt:
        print("\n[INFO] Encerrando o detector... Por favor, aguarde.")
        generate_reports() # <--- CHAMADA PARA GERAR OS RELATÓRIOS
        stop_event.set()
        time.sleep(1)
            
