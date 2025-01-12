# Network Anomaly Detector / Wykrywacz Anomalii Sieciowych

---

## 🌐 Language / Język

- [English](#english-version)
- [Polski](#wersja-polska)

---

## 📃 English Version

### 🛡️ Project Description

**Network Anomaly Detector** is an advanced cybersecurity tool designed to monitor network traffic and detect unusual activity using artificial intelligence. It helps identify potential security threats and provides automated responses to mitigate risks.

### 📊 Key Features

- ✅ **Detection of Network Attacks** (DDoS, Brute Force)
- ✅ **Automatic Blocking** of Suspicious IP Addresses
- ✅ **Email Notifications** for Detected Threats
- ✅ **Interactive Web Dashboard** with Graphs and Data Export

### 📚 Prerequisites

1. **Install Python 3.10 or higher**  
   Download Python from the official site: [Python.org](https://www.python.org/)

2. **Install Git (optional for version control)**  
   Download Git from: [Git-scm.com](https://git-scm.com/downloads)

3. **Install Required Python Packages**  
   Open a terminal (CMD, PowerShell) and run:
   
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Gmail for Email Notifications**
   - Go to [Google Account Security](https://myaccount.google.com/security).
   - Enable **2-Step Verification**.
   - Generate an **App Password** for your project.
   - Replace the placeholder in `anomaly_detector.py` with your app password.

5. **Allow Scapy to Capture Packets (Windows)**
   - Install **Npcap** from [Npcap](https://nmap.org/npcap/)
   - Run Python as **Administrator** to allow packet sniffing.

### 📚 How to Run the Project

1. **Clone the Repository**
   
   ```bash
   git clone https://github.com/YOUR_USERNAME/network_anomaly_detector.git
   cd network_anomaly_detector
   ```

2. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**

   ```bash
   python anomaly_detector.py
   ```

4. **Access the Web Dashboard**
   Open your browser and go to:
   
   ```
   http://127.0.0.1:8080
   ```

### 📚 Project Structure

```
network_anomaly_detector/
├── anomaly_detector.py  # Main program
├── requirements.txt   # Required Python libraries
├── templates/
│   └── dashboard.html  # Web dashboard interface
└── static/
    └── anomaly_plot.png  # Generated anomaly graph
```

---

## 📃 Wersja Polska

### 🛡️ Opis Projektu

**Wykrywacz Anomalii Sieciowych** to zaawansowane narzędzie do cyberbezpieczeństwa, które monitoruje ruch sieciowy i wykrywa nietypowe zachowania za pomocą sztucznej inteligencji. Pomaga identyfikować potencjalne zagrożenia i automatycznie na nie reaguje.

### 📊 Kluczowe Funkcje

- ✅ **Wykrywanie Ataków Sieciowych** (DDoS, Brute Force)
- ✅ **Automatyczne Blokowanie** Podejrzanych Adresów IP
- ✅ **Powiadomienia E-mail** o Wykrytych Zagrożeniach
- ✅ **Interaktywny Panel WWW** z Wykresami i Eksportem Danych

### 📚 Wymagania Wstępne

1. **Zainstaluj Python 3.10 lub nowszy**  
   Pobierz Python z oficjalnej strony: [Python.org](https://www.python.org/)

2. **Zainstaluj Git (opcjonalnie)**  
   Pobierz Git: [Git-scm.com](https://git-scm.com/downloads)

3. **Zainstaluj wymagane biblioteki**  
   Otwórz terminal i wpisz:

   ```bash
   pip install -r requirements.txt
   ```

4. **Skonfiguruj Gmail do powiadomień e-mail**
   - Przejdź do [Bezpieczeństwo Google](https://myaccount.google.com/security).
   - Włącz **weryfikację dwuetapową**.
   - Wygeneruj **Hasło Aplikacji** dla projektu.
   - Wstaw hasło do pliku `anomaly_detector.py`.

5. **Pozwól Scapy przechwytywać pakiety (Windows)**
   - Zainstaluj **Npcap** z [Npcap](https://nmap.org/npcap/).
   - Uruchom Python jako **Administrator**.

### 📚 Uruchomienie Projektu

1. **Sklonuj Repozytorium**

   ```bash
   git clone https://github.com/YOUR_USERNAME/network_anomaly_detector.git
   cd network_anomaly_detector
   ```

2. **Zainstaluj zależności**

   ```bash
   pip install -r requirements.txt
   ```

3. **Uruchom Aplikację**

   ```bash
   python anomaly_detector.py
   ```

4. **Otwórz Panel WWW**
   Wejdź w przeglądarkę:

   ```
   http://127.0.0.1:8080
   ```

### 📚 Struktura Projektu

```
network_anomaly_detector/
├── anomaly_detector.py  # Główny program
├── requirements.txt   # Wymagane biblioteki
├── templates/
│   └── dashboard.html  # Interfejs panelu WWW
└── static/
    └── anomaly_plot.png  # Wygenerowany wykres
```

---

### 🛡️ Enjoy using the Network Anomaly Detector! / Miłego korzystania z Wykrywacza Anomalii Sieciowych! 🚀

