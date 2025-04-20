import whois
import requests
from bs4 import BeautifulSoup
import tldextract
import re
import socket
import urllib.parse

# Disabilita i warning SSL
requests.packages.urllib3.disable_warnings()


def scan_website(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Errore nella connessione: {e}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')

    # Estrai dominio
    parsed_url = tldextract.extract(url)
    domain = f"{parsed_url.domain}.{parsed_url.suffix}"

    # Ottieni IP
    ip_address = get_ip_address(url)

    # Trova email nel sito
    emails = find_emails(response.text)

    # Ottieni registrar e email
    registrar, registrar_email = get_registrar(domain)

    # Output finale
    print("\n--- Strumento per Segnalazioni - by zero_byte ---\n")
    print(f"Dominio: {domain}")
    print(f"Indirizzo IP: {ip_address}")
    print(f"Email trovate nel sito: {', '.join(emails) if emails else 'Nessuna'}")
    print(f"Registrar: {registrar}")
    print(f"Email del registrar: {', '.join(registrar_email) if registrar_email else 'Nessuna trovata'}")
    print("\n-----------------------------------------------\n")


def get_ip_address(url):
    try:
        hostname = urllib.parse.urlparse(url).hostname
        return socket.gethostbyname(hostname)
    except Exception:
        return "IP non disponibile"


def find_emails(text):
    return re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)


def get_registrar(domain):
    try:
        whois_info = whois.whois(domain)
        registrar = whois_info.registrar or "Non disponibile"
        registrar_email = whois_info.emails
        if isinstance(registrar_email, str):
            registrar_email = [registrar_email]
        return registrar, registrar_email
    except Exception:
        return "Non disponibile", None


# Esegui la scansione
url = input("Inserisci l'URL del sito da analizzare: ")
scan_website(url)
