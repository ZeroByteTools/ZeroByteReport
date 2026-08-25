import whois
import requests
from bs4 import BeautifulSoup
import tldextract
import re
import socket
import urllib.parse
from ipwhois import IPWhois
import ssl
import datetime

# Disabilita i warning SSL per le richieste HTTP
requests.packages.urllib3.disable_warnings()

def get_ssl_expiry(domain):
    """Ottiene la data di scadenza del certificato SSL"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Estrae la data di scadenza
                expiry_str = cert['notAfter']
                expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                return expiry_date.strftime('%d-%m-%Y')
    except Exception:
        return "Non disponibile o scaduto"

def get_ip_address(domain):
    """Risolve il dominio in un indirizzo IP"""
    try:
        clean_domain = domain.split('/')[0].split(':')[0]
        return socket.gethostbyname(clean_domain)
    except Exception:
        return "IP non disponibile"

def find_emails(text):
    """Trova le email nel testo escludendo falsi positivi comuni"""
    found = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    # Rimuove immagini o estensioni comuni scambiate per email
    clean_found = [email for email in found if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg'))]
    return list(set(clean_found))

def get_registrar(domain):
    """Ottiene i dati del registrar del dominio"""
    try:
        whois_info = whois.whois(domain)
        registrar = whois_info.registrar or "Non disponibile"
        registrar_email = whois_info.emails
        
        if not registrar_email:
            return registrar, []
        if isinstance(registrar_email, str):
            registrar_email = [registrar_email]
            
        return registrar, registrar_email
    except Exception:
        return "Non disponibile", []

def get_hosting_info(ip_address):
    """Ottiene i dati dell'hosting provider tramite IP"""
    if ip_address == "IP non disponibile":
        return "Non disponibile", []
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        hosting_provider = results.get('network', {}).get('name', 'Non disponibile')
        emails = results.get('network', {}).get('abuse_emails', [])
        
        if isinstance(emails, str):
            emails = [emails]
        return hosting_provider, emails
    except Exception:
        return "Non disponibile", []

def scan_website(url):
    """Funzione principale di scansione"""
    if not url.startswith(('http://', 'https://')):
        url_for_request = 'https://' + url
    else:
        url_for_request = url

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    print("\n⏱️ [+] Avvio analisi in corso (potrebbe richiedere qualche secondo)...")

    # 1. Richiesta HTTP e stato del sito
    try:
        response = requests.get(url_for_request, headers=headers, verify=False, timeout=15, allow_redirects=True)
        status_code = response.status_code
    except requests.exceptions.RequestException as e:
        print(f"❌ Errore nella connessione: {e}")
        return

    # 2. Estrazione dati dal testo e dominio
    parsed_url = tldextract.extract(url_for_request)
    domain = f"{parsed_url.domain}.{parsed_url.suffix}"
    
    ip_address = get_ip_address(domain)
    emails = find_emails(response.text)
    registrar, registrar_email = get_registrar(domain)
    hosting_provider, hosting_emails = get_hosting_info(ip_address)
    ssl_expiry = get_ssl_expiry(domain)

    # 3. Generazione del testo del Report
    report_output = (
        f"===============================================\n"
        f"      REPORT SEGNALAZIONE - by zero_byte       \n"
        f"===============================================\n\n"
        f"🌐 Dominio analizzato:  {domain}\n"
        f"🚦 Stato HTTP:          {status_code}\n"
        f"🔒 Scadenza SSL:        {ssl_expiry}\n"
        f"📍 Indirizzo IP:        {ip_address}\n"
        f"🏢 Hosting Provider:     {hosting_provider}\n"
        f"📩 Email Abuso Hosting: {', '.join(hosting_emails) if hosting_emails else 'Nessuna trovata'}\n"
        f"📝 Registrar Dominio:   {registrar}\n"
        f"📩 Email Registrar:     {', '.join(registrar_email) if registrar_email else 'Nessuna trovata'}\n"
        f"📧 Email nel Sito Web:  {', '.join(emails) if emails else 'Nessuna trovata'}\n\n"
        f"===============================================\n"
    )

    # Stampa a schermo
    print(report_output)

    # 4. Salvataggio automatico su file
    salva = input("Vuoi salvare questo report in un file .txt? (s/n): ").lower()
    if salva == 's':
        filename = f"report_{domain.replace('.', '_')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write(report_output)
            print(f"💾 Report salvato con successo nel file: {filename}")
        except Exception as e:
            print(f"❌ Impossibile salvare il file: {e}")

if __name__ == "__main__":
    url = input("Inserisci l'URL o il dominio del sito da analizzare: ")
    scan_website(url)
