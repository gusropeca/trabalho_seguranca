import requests
import time

# --- Configurações da Simulação ---
# URL de um site que responde rápido. Usar um site grande como o Google é seguro.
TARGET_URL = "https://www.google.com"
# Número de requisições que vamos fazer para gerar tráfego
NUM_REQUESTS = 200

print(f"[*] Simulador de Tráfego de Rede")
print(f"[*] Alvo: {TARGET_URL}")
print(f"[*] Enviando {NUM_REQUESTS} requisições para gerar pacotes...")

# Loop para enviar as requisições
for i in range(NUM_REQUESTS):
    try:
        # Faz uma requisição GET. O timeout baixo evita que o script fique preso.
        requests.get(TARGET_URL, timeout=1)
        # Imprime o progresso na mesma linha para não poluir o terminal
        print(f"--> Pacotes da requisição {i + 1}/{NUM_REQUESTS} enviados.", end='\r')
    except requests.exceptions.RequestException as e:
        # Se houver um erro de rede (normal acontecer), apenas imprime e continua.
        # print(f"Erro na requisição {i+1}: {e}")
        pass

print("\n[*] Simulação de tráfego de rede concluída!")