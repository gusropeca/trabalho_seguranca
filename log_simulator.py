import time
from datetime import datetime

# --- Configurações da Simulação ---
LOG_FILE = 'access.log'
NUM_ENTRIES = 101  # Quantas linhas de log vamos gerar?
ATTACKER_IP = '198.51.100.10' # IP do nosso "atacante"

# Monta a linha de log que será escrita no arquivo
# Usamos .now() para que o timestamp seja sempre atual
timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')
LOG_LINE_FORMAT = f'{ATTACKER_IP} - user [ {timestamp}] "GET /login.php HTTP/1.1" 401 130\n'

print(f"[*] Simulando ataque: Gerando {NUM_ENTRIES} entradas de log no arquivo '{LOG_FILE}'...")
print(f"[*] IP do Atacante: {ATTACKER_IP}")

try:
    # O modo 'a' significa 'append' (adicionar ao final do arquivo),
    # para não apagar o que já existe.
    with open(LOG_FILE, 'a') as f:
        for i in range(NUM_ENTRIES):
            f.write(LOG_LINE_FORMAT)
            # Imprime o progresso na mesma linha
            print(f"--> Entrada {i + 1}/{NUM_ENTRIES} gerada.", end='\r')
            time.sleep(0.1) # Um pequeno atraso para tornar a simulação visível

    print("\n[*] Simulação de log concluída! Verifique o terminal do detector.")

except Exception as e:
    print(f"\n[ERRO] Não foi possível escrever no arquivo: {e}")