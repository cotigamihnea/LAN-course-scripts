import sys
import ipaddress 

def clear():
    print("\n" + "="*60 + "\n")

def print_cmd(description, command):
    print(f"\n---> {description}:")
    print(f"\033[92m{command}\033[0m") 
    print("-" * 40)

def print_check(location, command):
    print(f"\033[93m[VERIFICARE - TESTARE]\033[0m")
    print(f"1. Intră pe: \033[1m{location}\033[0m")
    print(f"2. Rulează:  \033[96m{command}\033[0m")
    print("-" * 40)

# --- MENIURI EXISTENTE (IP, NAT, FIREWALL etc.) ---
# ... (Au rămas la fel ca în v24, le păstrăm aici pentru completitudine) ...

def menu_ip():
    print("--- CONFIGURARE IP (ALEGE METODA) ---")
    print("1. Configurare LEGĂTURĂ (Subnet -> Host + Container)")
    print("2. Configurare Manuală (Un singur IP)")
    opt = input("\nAlege (1-2): ")
    if opt == '1':
        print("\n--- CALCULATOR LEGĂTURĂ (Host <-> Container) ---")
        try:
            subnet_str = input("Introdu Subrețeaua (ex: 10.200.40.128/29): ")
            iface_host = input("Nume interfață HOST (ex: veth-red): ")
            iface_cont = input("Nume interfață CONTAINER (ex: eth0): ")
            net = ipaddress.ip_network(subnet_str, strict=False)
            hosts = list(net.hosts())
            if len(hosts) < 2: return
            ip_host = f"{hosts[0]}/{net.prefixlen}"     
            ip_cont = f"{hosts[1]}/{net.prefixlen}"     
            gateway = hosts[0]                          
            print("\n" + "="*20 + " COMENZI DE RULAT " + "="*20)
            print(f"\n1. Rulează asta pe HOST (Terminalul principal):")
            print(f"\033[92mip addr add {ip_host} dev {iface_host}\033[0m")
            print(f"\033[92mip link set dev {iface_host} up\033[0m")
            print(f"\n2. Rulează asta pe CONTAINER (Intră cu 'go ...'):")
            print(f"\033[92mip addr add {ip_cont} dev {iface_cont}\033[0m")
            print(f"\033[92mip link set dev {iface_cont} up\033[0m")
            print(f"\033[92mip route add default via {gateway}\033[0m")
            print("-" * 50)
            print_check(f"CONTAINERUL {iface_cont}", f"ping {gateway}")
        except ValueError: print("\n[EROARE] Format Subnet invalid!")
    elif opt == '2':
        iface = input("Interfața (ex: eth0): ")
        ip = input("Adresa IP/CIDR (ex: 192.168.1.10/24): ")
        gw = input("Gateway (Enter dacă nu ai): ")
        if iface and ip:
            print("\nCOPIAZĂ ȘI RULEAZĂ:")
            print("-" * 40)
            print(f"ip addr add {ip} dev {iface}")
            print(f"ip link set dev {iface} up")
            if gw: print(f"ip route add default via {gw}")

def menu_ipv6():
    print("--- CONFIGURARE IPv6 ---")
    print("1. Adăugare Adresă IPv6")
    print("2. Activare Rutare IPv6 (Forwarding)")
    print("3. Adăugare Rută Default IPv6")
    print("4. Verificare (Ping6 & Show)")
    opt = input("\nAlege (1-4): ")
    if opt == '1':
        iface = input("Interfața (ex: eth0): ")
        ip = input("Adresa IPv6 (ex: 2201::1/64): ")
        if iface and ip:
            print_cmd("Adăugare IP IPv6", f"ip -6 addr add {ip} dev {iface}")
            print_cmd("Ridicare interfață", f"ip link set dev {iface} up")
            print_check(f"HOST (local)", f"ip -6 addr show {iface}")
    elif opt == '2': print_cmd("Activare Forwarding IPv6", "sysctl -w net.ipv6.conf.all.forwarding=1")
    elif opt == '3':
        gw = input("Gateway IPv6 (ex: 2201::1): ")
        if gw: print_cmd("Adăugare Default Gateway IPv6", f"ip -6 route add default via {gw}")
    elif opt == '4':
        print_cmd("Afișare Adrese IPv6", "ip -6 addr show")
        target = input("Țintă Ping (ex: 2201::1): ")
        if target: print_cmd("Ping IPv6", f"ping -6 {target}")

def menu_routing():
    print("--- ACTIVARE RUTARE IPv4 (Host -> Router) ---")
    print_cmd("Comanda pentru activare", "sysctl -w net.ipv4.ip_forward=1")
    print_check("HOST", "cat /proc/sys/net/ipv4/ip_forward")

def menu_nat():
    print("--- CONFIGURARE NAT & POSTROUTING (Lab 8) ---")
    print("1. MASQUERADE (IP Dinamic - Standard pentru Internet)")
    print("2. SNAT (IP Static sau Range de Porturi)")
    opt = input("\nAlege (1-2): ")
    if opt == '1':
        iface = input("Interfața de IEȘIRE la net (Enter = Orice): ")
        out_flag = f"-o {iface}" if iface else ""
        print_cmd("NAT Dinamic (Masquerade)", f"iptables -t nat -A POSTROUTING {out_flag} -j MASQUERADE")
        print_check("ORICE CONTAINER", "ping 8.8.8.8")
    elif opt == '2':
        src_net = input("Rețea Sursă (ex: 192.168.1.0/24 sau IP Red): ")
        to_source = input("IP Ieșire (și opțional porturi) (ex: 1.2.3.4:45000-50000): ")
        iface = input("Interfața de IEȘIRE (Enter = Orice): ")
        out_flag = f"-o {iface}" if iface else ""
        if src_net and to_source:
            print_cmd("SNAT Static", f"iptables -t nat -A POSTROUTING -s {src_net} {out_flag} -j SNAT --to-source {to_source}")
            print_check(f"CONTAINERUL SURSĂ ({src_net})", "curl ifconfig.me")

def resolve_port(port_input):
    services = {'ssh': '22', 'telnet': '23', 'ftp': '21', 'http': '80', 'https': '443', 'dns': '53'}
    clean_input = port_input.strip().lower()
    if clean_input.isdigit(): return clean_input
    if clean_input in services:
        print(f"\033[92m[INFO] Am convertit automat '{clean_input}' în portul {services[clean_input]}.\033[0m")
        return services[clean_input]
    print(f"\n\033[93m[ATENȚIE] Nu recunosc portul '{clean_input}'! Folosesc textul ca atare.\033[0m")
    return clean_input

def menu_dnat():
    print("--- PORT FORWARDING & DNAT (Lab 9) ---")
    print("1. TCP - CLASIC (Oricine -> Host:Port -> Container:Port)")
    print("2. TCP - SPECIFIC (De la Sursă X -> Host:Port -> Container:Port)")
    print("3. ICMP - Redirectare PING")
    opt = input("\nAlege (1-3): ")
    src_ip = ""
    src_part = ""
    if opt == '3':
        print("\n--- REDIRECTARE PING (ICMP) ---")
        use_src = input("Specifici sursa? (y/n): ")
        if use_src.lower() == 'y':
            src_ip = input("IP Sursă (ex: Green): ")
            src_part = f"-s {src_ip} "
        int_ip = input("IP Destinație (ex: Blue): ")
        cmd = f"iptables -t nat -A PREROUTING {src_part}-p icmp -j DNAT --to-destination {int_ip}"
        print_cmd("Comanda Redirect Ping", cmd)
        return
    if opt == '2':
        src_ip = input("IP Sursă (ex: IP Green): ")
        src_part = f"-s {src_ip} "
    while True:
        ext_port = input("Port Extern (pe Host) [ex: 12345]: ")
        if ext_port == "22": print("\n\033[91m[EROARE] Nu poți folosi portul 22 pe Host!\033[0m")
        else: break
    int_ip = input("IP Destinație (ex: IP Blue): ")
    while True:
        raw_int_port = input("Port Destinație (ex: 22, ssh): ")
        int_port = resolve_port(raw_int_port)
        if int_port: break
    if ext_port and int_ip and int_port:
        cmd = f"iptables -t nat -A PREROUTING {src_part}-p tcp --dport {ext_port} -j DNAT --to-destination {int_ip}:{int_port}"
        print_cmd("Comanda Port Forwarding", cmd)
        check_cmd = f"nc -v [IP_HOST] {ext_port}"
        if int_port == '22': check_cmd = f"ssh -p {ext_port} student@[IP_HOST]"
        elif int_port == '23': check_cmd = f"telnet [IP_HOST] {ext_port}"
        elif int_port in ['80', '443']: check_cmd = f"curl [IP_HOST]:{ext_port}"
        if opt == '2': print_check(f"Stația SURSĂ ({src_ip})", check_cmd)
        else: print_check("HOST (Local)", check_cmd.replace("[IP_HOST]", "localhost"))

def menu_firewall():
    print("--- FIREWALL & FILTERING (IPTABLES) ---")
    print("1. Blochează un IP care intră AICI (INPUT)")
    print("2. Permite doar SSH de la un IP (INPUT)")
    print("3. Blochează traficul RUTAT (FORWARD - Specific)")
    print("4. Blochează traficul LOCAL (OUTPUT - Ex: Host spre Site)")
    print("5. Inserare regulă FORWARD (Prioritate)")
    print("6. Șterge reguli (Flush)")
    print("7. WHITELIST FORWARD (Permite X, Blochează Restul)")
    print("8. Control ASIMETRIC (A->B Permis, B->A Blocat)")
    print("9. BLOCK C2 (Toată rețeaua -> Atacator)")
    opt = input("\nAlege scenariul (1-9): ")
    if opt == '1':
        ip = input("IP-ul de blocat: ")
        if ip: 
            print_cmd(f"Blocare trafic de la {ip}", f"iptables -A INPUT -s {ip} -j DROP")
            print_check(f"Stația BLOCATĂ ({ip})", f"ping [IP_HOST]")
    elif opt == '2':
        ip = input("IP-ul Sursă permis: ")
        if ip:
            print(f"\033[92miptables -A INPUT -s {ip} -p tcp --dport 22 -j ACCEPT\033[0m")
            print(f"\033[92miptables -A INPUT -s {ip} -j DROP\033[0m")
    elif opt == '3':
        dest = input("Destinația blocată (IP/Hostname): ")
        proto = input("Protocol/Port (telnet/ftp/ssh/22/23): ")
        if dest and proto:
            print_cmd(f"Blocare {proto} către {dest}", f"iptables -A FORWARD -d {dest} -p tcp --dport {proto} -j REJECT")
    elif opt == '4':
        dest = input("Destinația blocată (IP/Hostname): ")
        proto = input("Protocol/Port (telnet/ftp/ssh/22/23): ")
        if dest and proto:
            print_cmd(f"Blocare {proto} către {dest}", f"iptables -A OUTPUT -d {dest} -p tcp --dport {proto} -j REJECT")
    elif opt == '5':
        dest = input("Destinația (IP/Hostname): ")
        if dest: print_cmd("Permite SSH cu prioritate", f"iptables -I FORWARD 1 -p tcp -d {dest} --dport 22 -j ACCEPT")
    elif opt == '6':
        print_cmd("Resetare COMPLETĂ Firewall", "iptables -F\niptables -t nat -F")
    elif opt == '7':
        print("\n--- WHITELIST FORWARD ---")
        src = input("IP Sursă: ")
        dst = input("IP Destinație: ")
        allow_tcp = input("Port TCP permis: ")
        if src and dst:
            if allow_tcp: print(f"\033[92miptables -A FORWARD -s {src} -d {dst} -p tcp --dport {allow_tcp} -j ACCEPT\033[0m")
            print(f"\033[92miptables -A FORWARD -s {src} -d {dst} -j DROP\033[0m")
    elif opt == '8':
        print("\n--- CONTROL ASIMETRIC ---")
        ip_a = input("IP Sursă (POATE iniția): ")
        ip_b = input("IP Destinație (NU POATE iniția): ")
        port = input("Portul (ex: 22): ")
        real_port = resolve_port(port)
        if ip_a and ip_b and real_port:
            print(f"\033[92miptables -A FORWARD -s {ip_a} -d {ip_b} -p tcp --dport {real_port} -m state --state NEW -j ACCEPT\033[0m")
            print(f"\033[92miptables -A FORWARD -s {ip_b} -d {ip_a} -p tcp --dport {real_port} -m state --state NEW -j REJECT\033[0m")
    elif opt == '9':
        attacker = input("IP Atacator (C2): ")
        if attacker:
            cmd = f"iptables -I FORWARD -d {attacker} -j DROP"
            print_cmd("Comanda Blocare C2", cmd)

def menu_ssh_scp():
    print("--- SSH, SCP & DIRECTOARE ---")
    print("1. SSH Simplu")
    print("2. SCP Download (-r)")
    print("3. SCP Upload (-r)")
    print("4. Tunel Invers")
    print("5. Configurare Manuală Chei")
    opt = input("Alege (1-5): ")
    if opt == '1':
        print_cmd("Generare & Copiere", "ssh-keygen -t rsa && ssh-copy-id user@host")
    elif opt == '2':
        remote_dir = input("Dir Remote: ")
        user_host = input("User@Host: ")
        if remote_dir: print_cmd("Download", f"scp -r {user_host}:{remote_dir} .")
    elif opt == '3':
        local_dir = input("Dir Local: ")
        user_host = input("User@Host: ")
        if local_dir: print_cmd("Upload", f"scp -r {local_dir} {user_host}:~")
    elif opt == '4':
        r_port = input("Port Remote: ")
        l_port = input("Port Local: ")
        host = input("User@Server: ")
        if r_port: print_cmd("Tunel Invers", f"ssh -R {r_port}:localhost:{l_port} {host}")
    elif opt == '5':
        print("\n--- PROCEDURA MANUALĂ ---")
        print_cmd("PAS 1: Generare", "ssh-keygen -t rsa")
        print_cmd("PAS 2: Afișare cheie", "cat ~/.ssh/id_rsa.pub")
        print_cmd("PAS 4: Testare", "ssh user@host")

def menu_perf_transfer():
    print("--- TESTARE PERFORMANȚĂ TRANSFER ---")
    print("1. Transfer Direct (Netcat)")
    opt = input("Alege (1): ")
    if opt == '1':
        print_check("HOST", "nc -l 12345 > fisier.dat")
        print_check("CLIENT", "cat fisier.dat | nc -q0 host 12345")

def menu_tools():
    print("--- ANALIZĂ TRAFIC & SCANARE ---")
    print("1. Captură Simplă")
    print("2. Sniffing ASCII")
    print("3. Scanare Nmap")
    print("4. Citește fișier PCAP (OSI)")
    print("5. Raport Rapid (Top Talkers)")
    print("6. Metoda NETSTAT (în container)")
    print("7. Metoda LIVE PAYLOAD")
    opt = input("Alege (1-7): ")
    if opt == '1':
        iface = input("Interfața (Enter = Toate): ")
        file = input("Fișier (Enter = captura.pcap): ").strip() or "captura.pcap"
        print_cmd("Start Captură", f"tcpdump -i {iface if iface else 'any'} -w {file}")
    elif opt == '2':
        iface = input("Interfața (Enter = Toate): ")
        print_cmd("Sniffing ASCII", f"tcpdump -vvv -A -i {iface if iface else 'any'}")
    elif opt == '3':
        target = input("Target: ")
        print("1. Standard")
        print("2. Exam Fast (Recomandat)")
        scan_type = input("Alege (1-2): ")
        if scan_type == '2': print_cmd("Scanare Rapidă", f"nmap -F -sV {target}")
        else: print_cmd("Scanare Detaliată", f"nmap -sV -O {target}")
    elif opt == '4':
        file = input("Fișier PCAP: ") or "captura.pcap"
        sub = input("Nivel (a=L2, b=L3, c=L4, d=L7): ")
        if sub == 'a': print_cmd("L2", f"tcpdump -e -r {file}")
        elif sub == 'b': print_cmd("L3", f"tcpdump -n -r {file}")
        elif sub == 'c': print_cmd("L4", f"tcpdump -r {file} tcp or udp")
        elif sub == 'd': print_cmd("L7", f"tcpdump -A -r {file}")
    elif opt == '5':
        file = input("Fișier PCAP: ") or "captura.pcap"
        cmd = f"tcpdump -r {file} -n -q ip | awk '{{print $3 \" -> \" $5}}' | sort | uniq -c | sort -nr | head -n 10"
        print_cmd("Raport Top Talkers", cmd)
    elif opt == '6':
        print_cmd("Vezi conexiuni", "netstat -tupna | grep ESTABLISHED")
    elif opt == '7':
        iface = input("Interfața: ")
        print_cmd("Live Payload", f"tcpdump -n -A -i {iface} port not 22")

def menu_traffic_gen():
    print("--- GENERATOR TRAFIC (TESTE) ---")
    print("1. Accesare Web (CURL)")
    print("2. Aflare IP (DNS)")
    print("3. Conectare Telnet/Ping")
    opt = input("Alege (1-3): ")
    if opt == '1':
        url = input("URL/Site: ")
        if url: print_cmd("Accesare Site", f"curl {url}")
    elif opt == '2':
        site = input("Domeniu: ")
        if site: print_cmd("Aflare IP", f"host {site}")
    elif opt == '3':
        target = input("IP/Domeniu: ")
        if target: 
            print_cmd("Ping", f"ping {target}")
            print_cmd("Telnet", f"telnet {target}")

def menu_troubleshoot():
    print("\n\033[91m=== GHID DEPANARE & ERORI UZUALE ===\033[0m")
    print("1. IP PUS GREȘIT: ip addr del [IP] dev eth0")
    print("2. PING BLOCAT:   iptables -F")
    print("3. NO INTERNET:   sysctl, iptables MASQUERADE, ip route")

# --- MENIU NOU: NAMESPACES ---
def menu_namespaces():
    print("--- NAMESPACES & ADVANCED NETWORKING (Lab 10) ---")
    print("1. Creare Namespace (netns)")
    print("2. Lista Namespace-uri")
    print("3. Executare comandă în Namespace")
    print("4. Creare pereche VETH")
    print("5. Mutare interfață în Namespace")
    print("6. Configurare IP în Namespace")
    print("7. Creare Bridge și conectare interfețe")
    
    opt = input("\nAlege (1-7): ")
    
    if opt == '1':
        name = input("Nume Namespace (ex: ns1): ")
        if name: print_cmd(f"Creare {name}", f"ip netns add {name}")
    elif opt == '2':
        print_cmd("Listare", "ip netns list")
    elif opt == '3':
        ns = input("Namespace (ex: ns1): ")
        cmd = input("Comanda (ex: ip link list): ")
        if ns and cmd: print_cmd(f"Exec în {ns}", f"ip netns exec {ns} {cmd}")
    elif opt == '4':
        v1 = input("Nume veth1 (ex: veth0): ")
        v2 = input("Nume veth2 (ex: veth1): ")
        if v1 and v2: print_cmd("Creare Pereche VETH", f"ip link add {v1} type veth peer name {v2}")
    elif opt == '5':
        iface = input("Interfața de mutat (ex: veth1): ")
        ns = input("Namespace destinație (ex: ns1): ")
        if iface and ns: print_cmd(f"Mutare {iface} -> {ns}", f"ip link set {iface} netns {ns}")
    elif opt == '6':
        ns = input("Namespace (ex: ns1): ")
        iface = input("Interfața (ex: veth1): ")
        ip = input("IP/Masca (ex: 10.1.1.1/24): ")
        if ns and iface and ip:
            print("\nCOPIAZĂ ÎN ORDINE:")
            print(f"\033[92mip netns exec {ns} ip addr add {ip} dev {iface}\033[0m")
            print(f"\033[92mip netns exec {ns} ip link set dev {iface} up\033[0m")
    elif opt == '7':
        br_name = input("Nume Bridge (ex: br0): ")
        iface = input("Interfața de adăugat (ex: veth0): ")
        if br_name:
            print("\nCOPIAZĂ ÎN ORDINE:")
            print(f"\033[92mip link add {br_name} type bridge\033[0m")
            print(f"\033[92mip link set dev {br_name} up\033[0m")
            if iface: print(f"\033[92mip link set {iface} master {br_name}\033[0m")

def main():
    while True:
        clear()
        print("GENERATOR DE COMENZI - EXAMEN RL (v25.0 NAMESPACES)")
        print("1. IP & Interfețe")
        print("2. Rutare IPv4")
        print("3. NAT & POSTROUTING")
        print("4. Port Forwarding & DNAT")
        print("5. Firewall")
        print("6. SSH & SCP")
        print("7. Performanță Transfer")
        print("8. IPv6")
        print("9. Analiză Trafic")
        print("10. GENERARE TRAFIC")
        print("11. DIAGNOSTIC & ERORI")
        print("\033[96m12. NAMESPACES & ADVANCED NET (Lab 10)\033[0m")
        print("0. Ieșire")
        
        choice = input("\nCe vrei să faci? (0-12): ")
        
        if choice == '1': menu_ip()
        elif choice == '2': menu_routing()
        elif choice == '3': menu_nat()
        elif choice == '4': menu_dnat()
        elif choice == '5': menu_firewall()
        elif choice == '6': menu_ssh_scp()
        elif choice == '7': menu_perf_transfer()
        elif choice == '8': menu_ipv6()
        elif choice == '9': menu_tools()
        elif choice == '10': menu_traffic_gen()
        elif choice == '11': menu_troubleshoot()
        elif choice == '12': menu_namespaces()
        elif choice == '0': sys.exit()
        
        input("\nApasă Enter pentru a reveni la meniu...")

if __name__ == "__main__":
    main()