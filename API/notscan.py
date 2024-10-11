from scapy.all import sniff
from flask import Flask, render_template
import threading
from collections import defaultdict
import time

# Configuração para capturar e armazenar tentativas de conexão
connection_attempts = defaultdict(list)
alerts = []

# Função que detecta possíveis escaneamentos de portas
def detect_port_scan(packet):
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        src_ip = packet['IP'].src
        dst_port = packet['TCP'].dport
        
        # Armazena o tempo da tentativa de conexão por IP e porta
        connection_attempts[src_ip].append((dst_port, time.time()))
        
        # Se houver mais de 10 tentativas de conexão em portas diferentes, possível port scan
        if len(connection_attempts[src_ip]) > 10:
            alert_msg = f"Possível port scan detectado de {src_ip} para portas {set([p[0] for p in connection_attempts[src_ip]])}!"
            print(alert_msg)
            alerts.append(alert_msg)
            connection_attempts[src_ip] = []  # Limpa após o alerta

# Função que inicia a captura de pacotes em uma thread separada
def start_packet_capture():
    sniff(prn=detect_port_scan, filter="tcp", store=0)

# Função que inicializa o servidor Flask para exibir os alertas
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', alerts=alerts)

# Inicia o Flask em uma thread separada
def start_flask_server():
    app.run(host='0.0.0.0', port=5000)

# Inicializa a captura de pacotes e o servidor Flask em threads diferentes
if __name__ == "__main__":
    # Inicia a captura de pacotes em uma thread separada
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.start()

    # Inicia o servidor Flask em outra thread
    flask_thread = threading.Thread(target=start_flask_server)
    flask_thread.start()
