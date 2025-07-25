from scapy.all import IP, TCP, send
import time

# --- Configurações da Simulação ---
TARGET_IP = "8.8.8.8"      # IP do DNS do Google, um alvo robusto
TARGET_PORT = 53           # Porta 53 (DNS) é comumente usada para testes de inundação
NUM_PACKETS = 300          # Número de pacotes a serem enviados

# --- Construção do Pacote ---
# Criamos um pacote IP/TCP simples. O conteúdo não importa, apenas o volume.
packet = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S")

print(f"[*] Simulador de Tráfego Otimizado (Modo Scapy)")
print(f"[*] Alvo: {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Enviando {NUM_PACKETS} pacotes o mais rápido possível...")

# --- Loop de Envio Rápido ---
start_time = time.time()

# A função send() com verbose=0 é extremamente rápida.
for _ in range(NUM_PACKETS):
    send(packet, verbose=0)

end_time = time.time()
duration = end_time - start_time

print(f"[*] Simulação concluída!")
print(f"[*] {NUM_PACKETS} pacotes enviados em {duration:.2f} segundos.")

if duration > 0:
    pps = NUM_PACKETS / duration
    print(f"[*] Média de {pps:.2f} pacotes por segundo (PPS).")
