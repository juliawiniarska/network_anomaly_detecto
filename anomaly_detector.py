# Krok 1: Instalacja wymaganych bibliotek
# pip install scapy pandas scikit-learn matplotlib joblib smtplib flask sqlalchemy requests geoip2 twilio openpyxl

import scapy.all as scapy
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib
matplotlib.use('Agg')  # Wyłącza GUI Matplotlib
import matplotlib.pyplot as plt
import joblib
import smtplib
from email.message import EmailMessage
from datetime import datetime
from flask import Flask, render_template, send_file, request
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import requests
import os

# Krok 2: Konfiguracja bazy danych

Base = declarative_base()
engine = create_engine('sqlite:///anomalies.db')
Session = sessionmaker(bind=engine)
session = Session()

class Anomaly(Base):
    __tablename__ = 'anomalies'
    id = Column(Integer, primary_key=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    packet_size = Column(Float)
    protocol = Column(Integer)
    src_country = Column(String)
    dst_port = Column(Integer)
    attack_type = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# Krok 3: Funkcja geolokalizacji IP

def get_country(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return response.get("country", "Unknown")
    except:
        return "Unknown"

# Krok 4: Klasyfikacja typów ataków

def classify_attack(row):
    if row['protocol'] == 6 and row['dst_port'] in [22, 23, 3389]:
        return 'Brute Force Attack'
    elif row['packet_size'] > 1500:
        return 'DDoS Attack'
    else:
        return 'Unknown'

# Krok 5: Funkcja do logowania anomalii do pliku

def log_anomaly_to_file(anomalies):
    with open('anomalies_log.txt', 'a') as file:
        for _, row in anomalies.iterrows():
            file.write(f"[{datetime.now()}] SRC: {row['src_ip']} ({row['src_country']}) DST: {row['dst_ip']} SIZE: {row['packet_size']} PROTOCOL: {row['protocol']} PORT: {row['dst_port']} ATTACK: {row['attack_type']}\n")

# Krok 6: Automatyczne blokowanie podejrzanych IP

def block_ip(ip_address):
    if ip_address.startswith("192.168.") or ip_address == "127.0.0.1":
        print(f"Nie można zablokować lokalnego IP: {ip_address}")
        return

    command = f'netsh advfirewall firewall add rule name="Block_{ip_address}" dir=in action=block remoteip={ip_address} enable=yes'
    result = os.system(command)

    if result == 0:
        print(f"Zablokowano IP: {ip_address}")
    else:
        print(f"Błąd blokowania IP: {ip_address}")

# Krok 7: Wysyłanie alertu e-mail

def send_email_alert(anomaly_count):
    sender_email = "julciagim@gmail.com"
    receiver_email = "paulaotfor@gmail.com"
    password = "ioii godw jzqa xuwc"

    msg = EmailMessage()
    msg.set_content(f"Uwaga! Wykryto {anomaly_count} anomalii w ruchu sieciowym.")
    msg['Subject'] = "Alert bezpieczeństwa - Wykryto anomalie"
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print("Wysłano alert e-mail.")
    except Exception as e:
        print(f"Błąd podczas wysyłania e-maila: {e}")

# Krok 8: Rozbudowana analiza pakietów

def capture_packets(interface, packet_count):
    packets = scapy.sniff(iface=interface, count=packet_count)
    packet_data = []
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src_country = get_country(pkt[scapy.IP].src)
            dst_port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else 0
            packet_data.append({
                'src_ip': pkt[scapy.IP].src,
                'dst_ip': pkt[scapy.IP].dst,
                'packet_size': len(pkt),
                'protocol': pkt[scapy.IP].proto,
                'src_country': src_country,
                'dst_port': dst_port
            })
    return pd.DataFrame(packet_data)

# Krok 9: Wykrywanie anomalii

def detect_anomalies(dataframe):
    model = IsolationForest(contamination=0.01)
    features = dataframe[['packet_size', 'protocol', 'dst_port']]
    model.fit(features)

    predictions = model.predict(features)
    dataframe['anomaly'] = predictions
    dataframe['attack_type'] = dataframe.apply(classify_attack, axis=1)
    anomalies = dataframe[dataframe['anomaly'] == -1]

    if not anomalies.empty:
        send_email_alert(len(anomalies))
        log_anomaly_to_file(anomalies)
        for ip in anomalies['src_ip']:
            block_ip(ip)
        save_anomaly_to_db(anomalies)
    else:
        print("Nie wykryto żadnych anomalii.")

# Krok 10: Wizualizacja anomalii na stronie

def plot_anomalies():
    # Tworzenie folderu 'static' jeśli nie istnieje
    if not os.path.exists('static'):
        os.makedirs('static')

    df = pd.read_sql(session.query(Anomaly).statement, session.bind)
    plt.figure(figsize=(10, 6))
    plt.plot(df['timestamp'], df['packet_size'], label='Pakiety')
    anomalies = df[df['attack_type'] != 'Unknown']
    plt.scatter(anomalies['timestamp'], anomalies['packet_size'], color='red', label='Anomalie')
    plt.xlabel('Czas')
    plt.ylabel('Rozmiar pakietu (B)')
    plt.title('Wykrywanie anomalii w ruchu sieciowym')
    plt.legend()
    plt.grid(True)
    
    # Zapis wykresu do katalogu 'static'
    plt.savefig('static/anomaly_plot.png')
    plt.close()  # Zamknięcie figury, aby uniknąć ostrzeżeń



def save_anomaly_to_db(anomalies):
    for _, row in anomalies.iterrows():
        anomaly = Anomaly(
            src_ip=row['src_ip'],
            dst_ip=row['dst_ip'],
            packet_size=row['packet_size'],
            protocol=row['protocol'],
            src_country=row['src_country'],
            dst_port=row['dst_port'],
            attack_type=row['attack_type']
        )
        session.add(anomaly)
    session.commit()
    print("Anomalie zapisane do bazy danych.")

# Krok 11: Interfejs webowy

app = Flask(__name__)

@app.route('/')
def dashboard():
    plot_anomalies()
    anomalies = session.query(Anomaly).all()
    lang = request.args.get('lang', 'pl')  # Domyślnie język polski
    return render_template('dashboard.html', anomalies=anomalies, lang=lang)

@app.route('/export')
def export():
    df = pd.read_sql(session.query(Anomaly).statement, session.bind)
    df.to_excel('anomalies_report.xlsx', index=False)
    return send_file('anomalies_report.xlsx', as_attachment=True)

# Krok 12: Uruchomienie programu

def main():
    df = capture_packets(interface='Wi-Fi', packet_count=100)
    detect_anomalies(df)
    app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == "__main__":
    main()
