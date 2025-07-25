Este trabalho consiste em um detector de ataques DDOS(Distributed Denial of Service ou Ataque Distribuído de Negação de Serviço) em Python.

O `detector.py` implementa um sistema de detecção de DDoS unificado. Ele utiliza **multithreading** para executar duas estratégias de monitoramento:

1.  Análise de Logs de Servidor Web: Uma thread monitora em tempo real um arquivo `access.log`, detectando um número excessivo de requisições de um mesmo endereço IP em uma janela de tempo configurável.
2.  Captura de Pacotes de Rede: Uma segunda thread utiliza a biblioteca Scapy para capturar pacotes de rede diretamente da interface, identificando um fluxo anormal de pacotes vindos de um único IP.

Ao detectar uma atividade suspeita por qualquer um dos métodos, o sistema emite um alerta e simula uma ação de bloqueio de firewall para o IP malicioso.

O repositório está organizado da seguinte forma:

- `detector.py`: O script principal do detector.
- `log_simulator.py`: Script auxiliar para simular um ataque gerando múltiplas entradas em um arquivo de log.
- `requirements.txt`: Arquivo com a lista de dependências Python do projeto.
- `README.md`: Este arquivo.


O detector precisa de permissões elevadas para capturar pacotes de rede. Para testar o detector, é preciso abrir 2 terminais: um como administrador e o outro normalmente.
Depois, navegue até a pasta do projeto e ative o ambiente virtual "source venv/Scripts/activate".
Em seguida,  Execute o script principal:
    ```bash
    python detector.py
    ```
O detector ficará rodando e monitorando em silêncio até que uma ameaça seja detectada.

No segundo terminal, com o ambiente  venv ativo, execute:  
  ```bash
  python log_simulator.py
  ```
Assim, será possível ver os alertas aparecedo no terminal do detector. 
Após o alerta aparecer no terminal, aperte Ctrl+C para gerar dois relatórios na pasta do projeto: 'report.html' e 'report.json'.
