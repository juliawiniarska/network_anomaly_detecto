# Network Anomaly Detector / Wykrywacz Anomalii Sieciowych

---

## 📃 English version

### 🛡️ Project description

**Network anomaly detector** is an advanced cybersecurity tool designed to monitor network traffic and detect unusual activity using artificial intelligence. It helps identify potential security threats and provides automated responses to mitigate risks.

### 📊 Key Features

- ✅ **Detection of network attacks** (DDoS, Brute Force)
- ✅ **Automatic blocking** of suspicious IP addresses
- ✅ **Email notifications** for detected threats
- ✅ **Interactive web dashboard** with graphs and data export

### 📚 Prerequisites

1. **Install Python 3.10 or higher**  
   Download Python from the official site: [Python.org](https://www.python.org/)

2. **Install Git (optional for version control)**  
   Download Git from: [Git-scm.com](https://git-scm.com/downloads)

3. **Install required Python packages**  
   Open a terminal (CMD, PowerShell) and run:
   
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Gmail for email notifications**
   - Go to [Google Account Security](https://myaccount.google.com/security).
   - Enable **2-Step Verification**.
   - Generate an **App Password** for your project.
   - Replace the placeholder in `anomaly_detector.py` with your app password.

5. **Allow scapy to capture packets (Windows)**
   - Install **Npcap** from [Npcap](https://nmap.org/npcap/)
   - Run Python as **Administrator** to allow packet sniffing.

### 📚 How to run the project

1. **Clone the repository**
   
   ```bash
   git clone https://github.com/juliawiniarska/network_anomaly_detecto.git
   cd network_anomaly_detector
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**

   ```bash
   python anomaly_detector.py
   ```

4. **Access the web dashboard**
   Open your browser and go to:
   
   ```
   http://127.0.0.1:8080
   ```

### 📚 Project structure

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

## 📃 Wersja polska

### 🛡️ Opis projektu

**Wykrywacz anomalii sieciowych** to zaawansowane narzędzie do cyberbezpieczeństwa, które monitoruje ruch sieciowy i wykrywa nietypowe zachowania za pomocą sztucznej inteligencji. Pomaga identyfikować potencjalne zagrożenia i automatycznie na nie reaguje.

### 📊 Kluczowe funkcje

- ✅ **Wykrywanie ataków sieciowych** (DDoS, Brute Force)
- ✅ **Automatyczne blokowanie** podejrzanych adresów IP
- ✅ **Powiadomienia e-mail** o wykrytych zagrożeniach
- ✅ **Interaktywny panel WWW** z zykresami i eksportem danych

### 📚 Wymagania wstępne

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

### 📚 Uruchomienie projektu

1. **Sklonuj repozytorium**

   ```bash
   git clone https://github.com/juliawiniarska/network_anomaly_detecto.git
   cd network_anomaly_detector
   ```

2. **Zainstaluj zależności**

   ```bash
   pip install -r requirements.txt
   ```

3. **Uruchom aplikację**

   ```bash
   python anomaly_detector.py
   ```

4. **Otwórz panel WWW**
   Wejdź w przeglądarkę:

   ```
   http://127.0.0.1:8080
   ```

### 📚 Struktura projektu

```
network_anomaly_detector/
├── anomaly_detector.py  # Główny program
├── requirements.txt   # Wymagane biblioteki
├── templates/
│   └── dashboard.html  # Interfejs panelu WWW
└── static/
    └── anomaly_plot.png  # Wygenerowany wykres
```

