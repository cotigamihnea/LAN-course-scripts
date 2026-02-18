import sys
import ipaddress
import math

# ==============================================================================
#                               FUNCȚII AJUTĂTOARE
# ==============================================================================

def cidr_to_mask(val):
    val = str(val).strip()
    if "." in val: return val
    try:
        net = ipaddress.IPv4Network(f"0.0.0.0/{val}", strict=False)
        return str(net.netmask)
    except ValueError: return "255.255.255.0"

def print_header(title):
    print("\n" + "█" * 70)
    print(f"  {title}")
    print("█" * 70)

def print_instructions(device_type):
    print(f"\n[PASUL 1] Dă click pe echipamentul: {device_type}")
    print(f"[PASUL 2] Selectează tab-ul de sus numit 'CLI'")
    print(f"[PASUL 3] Apasă tasta ENTER o dată sau de două ori.")
    print(f"[PASUL 4] Scrie (sau dă Paste) la următoarele comenzi:")
    print("-" * 50)
    print("enable")
    print("configure terminal")

def print_commands(commands, verification=None):
    for cmd in commands:
        print(cmd)
    print("exit")
    print("-" * 50)
    if verification:
        print(f"\n[VERIFICARE] Ca să testezi dacă a mers, scrie tot aici:")
        print(f"   >>> {verification}")
    print("\n" + "="*70 + "\n")

# ==============================================================================
#                       FUNCȚII STANDARD (OPȚIUNILE 1-10)
# ==============================================================================

def config_interfata_ip():
    print_header("1. CONFIGURARE IP (Router/Link)")
    interfata = input("Interfața (ex: g0/0, fa0/1, se0/0/0): ")
    ip = input("Adresa IP (ex: 192.168.1.1): ")
    masca_input = input("Masca (scrie '24' sau '255.255.255.0'): ")
    mask = cidr_to_mask(masca_input)
    cmds = [f"interface {interfata}", f"ip address {ip} {mask}"]
    if "s" in interfata.lower() and "vlan" not in interfata.lower():
        is_dce = input("   Este capătul DCE (Serial cu ceas)? [da/nu]: ").lower()
        if is_dce.startswith('d') or is_dce == 'y': cmds.append("clock rate 64000")
    cmds.append("no shutdown")
    cmds.append("exit")
    print_instructions("ROUTER sau SWITCH L3")
    print_commands(cmds, "do show ip interface brief")

def config_vlan_access():
    print_header("2. VLAN & PORTURI ACCESS")
    vlan_id = input("ID-ul VLAN-ului (ex: 10, 20): ")
    ports = input("Porturile (ex: fa0/1 SAU range fa0/1-5): ")
    cmds = [f"vlan {vlan_id}", "exit"]
    if "range" not in ports and ("-" in ports or "," in ports): cmds.append(f"interface range {ports}")
    else: cmds.append(f"interface {ports}")
    cmds.append("switchport mode access")
    cmds.append(f"switchport access vlan {vlan_id}")
    cmds.append("no shutdown") 
    cmds.append("exit")
    print_instructions("SWITCH")
    print_commands(cmds, "do show vlan brief")

def config_trunk():
    print_header("3. TRUNK")
    print("Configurează portul care duce trafic pentru mai multe VLAN-uri.")
    interfata = input("Interfața de legătură (ex: g0/1, fa0/24): ")
    cmds = [f"interface {interfata}", "switchport mode trunk"]
    allowed = input("Ce VLAN-uri lași să treacă? (Scrie 'all' sau lista ex: 10,20,100): ")
    if allowed.strip() == "": allowed = "all"
    cmds.append(f"switchport trunk allowed vlan {allowed}")
    cmds.append("no shutdown")
    cmds.append("exit")
    print_instructions("SWITCH")
    print_commands(cmds, "do show interfaces trunk")

def config_static_route():
    print_header("4. RUTĂ STATICĂ")
    dest_net = input("Rețeaua Destinație: ")
    masca_input = input("Masca Destinație: ")
    next_hop = input("Next Hop IP: ")
    mask = cidr_to_mask(masca_input)
    cmds = [f"ip route {dest_net} {mask} {next_hop}"]
    print_instructions("ROUTER")
    print_commands(cmds, "do show ip route static")

def config_default_route():
    print_header("5. RUTĂ DEFAULT")
    next_hop = input("IP-ul Vecinului / Next Hop: ")
    cmds = [f"ip route 0.0.0.0 0.0.0.0 {next_hop}"]
    print_instructions("ROUTER")
    print_commands(cmds, "do show ip route")

def config_management_ssh():
    print_header("6. SECURITATE SSH")
    ip_mgmt = input("IP-ul stației PC Management: ")
    cmds = [f"access-list 1 permit {ip_mgmt}", "line vty 0 15", "access-class 1 in", "password student", "login", "exit"]
    print_instructions("SWITCH sau ROUTER")
    print_commands(cmds, "do show running-config | section line vty")

def config_dhcp_server():
    print_header("7. SERVER DHCP")
    pool_name = input("Nume Pool: ")
    net_ip = input("Adresa Rețelei: ")
    masca_input = input("Masca Rețelei: ")
    gateway = input("Default Gateway: ")
    mask = cidr_to_mask(masca_input)
    cmds = [f"ip dhcp pool {pool_name}", f"network {net_ip} {mask}", f"default-router {gateway}", "exit"]
    print_instructions("ROUTER")
    print_commands(cmds, "do show ip dhcp binding")

def config_stp_priority():
    print_header("8. STP PRIORITY")
    vlan_id = input("VLAN ID: ")
    prio = input("Prioritate (4096 sau 8192): ")
    cmds = [f"spanning-tree vlan {vlan_id} priority {prio}"]
    print_instructions("SWITCH")
    print_commands(cmds, f"do show spanning-tree vlan {vlan_id}")

def config_static_mac():
    print_header("9. STATIC MAC")
    mac = input("Adresa MAC: ")
    vlan_id = input("VLAN ID: ")
    interface = input("Interfața: ")
    cmds = [f"mac-address-table static {mac} vlan {vlan_id} interface {interface}"]
    print_instructions("SWITCH")
    print_commands(cmds, "do show mac-address-table static")

def cheat_pc():
    print_header("10. COMENZI PC")
    print("ipconfig /all | ping <IP> | tracert <IP> | arp -a")
    print("TRUC: CTRL+SHIFT+6 pentru a debloca consola.")

# ==============================================================================
#                       OPȚIUNILE AUTOMATE (11, 12, 13)
# ==============================================================================

def auto_topology_generator():
    print_header("11. AUTO-TOPOLOGY (CALCULATOR VLSM)")
    try:
        base_net_str = input("Rețeaua de start (ex: 192.168.100.0/24): ")
        base_net = ipaddress.IPv4Network(base_net_str, strict=False)
        nr_subnets = int(input("Câte rețele distincte sunt?: "))
    except ValueError: return

    subnets_req = []
    for i in range(nr_subnets):
        print(f"\n--- REȚEAUA #{i+1} ---")
        name = input("   Numele Zonei: ")
        try: nr_routers = int(input("   Câte interfețe de ROUTER?: "))
        except: nr_routers = 1
        routers_info = []
        for r in range(nr_routers):
            r_name = input(f"     -> Nume Router: ")
            r_iface = input(f"     -> Interfața FIZICĂ: ")
            is_vlan = input("       -> Subinterfață (VLAN)? [da/nu]: ").lower()
            vlan_id = input("          -> VLAN ID: ") if is_vlan.startswith('d') or is_vlan=='y' else None
            routers_info.append({"name": r_name, "iface": r_iface, "vlan_id": vlan_id})
        try: nr_sw = int(input("   Câte Switch-uri (Mgmt)?: ")); nr_pc = int(input("   Câte PC-uri?: "))
        except: nr_sw=0; nr_pc=0
        subnets_req.append({"name": name, "routers": routers_info, "nr_sw": nr_sw, "nr_pc": nr_pc, "hosts_needed": nr_routers+nr_sw+nr_pc})

    subnets_req.sort(key=lambda x: x["hosts_needed"], reverse=True)
    current_ip = base_net.network_address
    allocated_data, configs_per_router, switch_configs, pc_configs = [], {}, [], []

    for req in subnets_req:
        needed = req["hosts_needed"] + 2
        prefix = 32 - math.ceil(math.log2(needed))
        if prefix > 30: prefix = 30 
        try:
            subnet = ipaddress.IPv4Network(f"{current_ip}/{prefix}", strict=False)
            if not subnet.subnet_of(base_net):
                print(f"!!! EROARE: Nu mai e loc pentru {req['name']}"); break
            allocated_data.append({"req": req, "subnet": str(subnet)})
            all_ips, mask, idx = list(subnet.hosts()), subnet.netmask, 0
            
            for r_info in req["routers"]:
                if idx < len(all_ips):
                    ip, idx = all_ips[idx], idx+1
                    rn = r_info["name"]
                    if rn not in configs_per_router: configs_per_router[rn] = []
                    configs_per_router[rn].append(f"! Segment: {req['name']}")
                    if r_info["vlan_id"]:
                        configs_per_router[rn].extend([f"interface {r_info['iface']}", "no shutdown", "exit", f"interface {r_info['iface']}.{r_info['vlan_id']}", f"encapsulation dot1Q {r_info['vlan_id']}", f"ip address {ip} {mask}", "exit"])
                    else:
                        configs_per_router[rn].extend([f"interface {r_info['iface']}", f"ip address {ip} {mask}", "no shutdown", "exit"])
                        if "s" in r_info['iface'].lower(): configs_per_router[rn].insert(-2, "! Verifică DCE: clock rate 64000")
            
            gw_ip = all_ips[0] if len(all_ips)>0 else ""
            for s in range(req["nr_sw"]):
                if idx < len(all_ips): switch_configs.append({"net": req["name"], "ip": all_ips[idx], "mask": mask, "gw": gw_ip}); idx += 1
            for p in range(req["nr_pc"]):
                if idx < len(all_ips): pc_configs.append({"net": req["name"], "ip": all_ips[idx], "mask": mask, "gw": gw_ip}); idx += 1
            current_ip = subnet.broadcast_address + 1
        except Exception: return

    print_output_blocks(configs_per_router, switch_configs, pc_configs)

def smart_manual_generator():
    print_header("12. SMART CONFIG (AI Subnetul -> Eu dau IP-urile)")
    try: nr_subnets = int(input("Câte rețele vrei să configurezi?: "))
    except: return
    configs_per_router, switch_configs, pc_configs = {}, [], []

    for i in range(nr_subnets):
        print(f"\n--- REȚEAUA #{i+1} ---")
        net_str = input("   CIDR (ex: 10.11.12.144/29): ")
        try:
            network, mask = ipaddress.IPv4Network(net_str, strict=False), ""
            all_ips, mask = list(network.hosts()), network.netmask
        except: continue
        net_name = input("   Nume zonă: ")
        r_name = input("   Nume Router: "); r_iface = input("   Interfața Router: ")
        is_vlan = input("   Subinterfață (VLAN)? [da/nu]: ").lower()
        vlan_id = input("      -> VLAN ID: ") if is_vlan.startswith('d') or is_vlan=='y' else None
        
        gw_ip, current_idx = all_ips[0], 1
        if r_name not in configs_per_router: configs_per_router[r_name] = []
        configs_per_router[r_name].append(f"! Segment: {net_name}")
        if vlan_id: configs_per_router[r_name].extend([f"interface {r_iface}", "no shutdown", "exit", f"interface {r_iface}.{vlan_id}", f"encapsulation dot1Q {vlan_id}", f"ip address {gw_ip} {mask}", "exit"])
        else:
            configs_per_router[r_name].extend([f"interface {r_iface}", f"ip address {gw_ip} {mask}", "no shutdown", "exit"])
            if "s" in r_iface.lower(): configs_per_router[r_name].insert(-2, "clock rate 64000")

        try: nr_sw = int(input("   Câte Switch-uri?: "))
        except: nr_sw = 0
        for _ in range(nr_sw):
            if current_idx < len(all_ips): switch_configs.append({"net": net_name, "ip": all_ips[current_idx], "mask": mask, "gw": gw_ip}); current_idx += 1
        try: nr_pc = int(input("   Câte PC-uri?: "))
        except: nr_pc = 0
        for _ in range(nr_pc):
            if current_idx < len(all_ips): pc_configs.append({"net": net_name, "ip": all_ips[current_idx], "mask": mask, "gw": gw_ip}); current_idx += 1

    print_output_blocks(configs_per_router, switch_configs, pc_configs)

def full_manual_generator():
    print_header("13. CONFIGURARE MANUALĂ DETALIATĂ")
    try: nr_subnets = int(input("Câte rețele configurezi?: "))
    except: return
    configs_per_router, switch_configs, pc_configs = {}, [], []

    for i in range(nr_subnets):
        print(f"\n--- REȚEAUA #{i+1} ---")
        net_name = input("   Nume Zonă: ")
        common_mask = cidr_to_mask(input("   Masca comună (ex: 24, 255...): "))
        try: nr_routers = int(input("   Câte interfețe Router?: "))
        except: nr_routers = 0
        gw_default = ""
        for r in range(nr_routers):
            r_name = input(f"     [R{r+1}] Nume: "); r_iface = input(f"     [R{r+1}] Interfața: "); r_ip = input(f"     [R{r+1}] IP: ")
            is_vlan = input("       Subinterfață? [da/nu]: ").lower()
            vlan_id = input("         VLAN ID: ") if is_vlan.startswith('d') else None
            if gw_default == "": gw_default = r_ip
            if r_name not in configs_per_router: configs_per_router[r_name] = []
            configs_per_router[r_name].append(f"! Segment: {net_name}")
            if vlan_id: configs_per_router[r_name].extend([f"interface {r_iface}", "no shutdown", "exit", f"interface {r_iface}.{vlan_id}", f"encapsulation dot1Q {vlan_id}", f"ip address {r_ip} {common_mask}", "exit"])
            else:
                configs_per_router[r_name].extend([f"interface {r_iface}", f"ip address {r_ip} {common_mask}", "no shutdown", "exit"])
                if "s" in r_iface.lower() and input("       Este DCE? [da/nu]: ").lower().startswith('d'): configs_per_router[r_name].insert(-2, "clock rate 64000")

        try: nr_sw = int(input("   Câte Switch-uri?: "))
        except: nr_sw = 0
        for s in range(nr_sw): switch_configs.append({"net": net_name, "ip": input(f"     [SW{s+1}] IP: "), "mask": common_mask, "gw": gw_default})
        try: nr_pc = int(input("   Câte PC-uri?: "))
        except: nr_pc = 0
        for p in range(nr_pc): pc_configs.append({"net": net_name, "ip": input(f"     [PC{p+1}] IP: "), "mask": common_mask, "gw": gw_default})

    print_output_blocks(configs_per_router, switch_configs, pc_configs)

def print_output_blocks(configs_per_router, switch_configs, pc_configs):
    print("\n" + "█" * 70)
    print(" REZULTAT GENERAT")
    print("█" * 70)
    print("\n" + "▒" * 40 + "\n CONFIGURARE ROUTERE\n" + "▒" * 40)
    for r, cmds in configs_per_router.items():
        print(f"\n>>> PENTRU: {r.upper()}"); print("-" * 50); [print(line) for line in cmds]; print("-" * 50)
    if switch_configs:
        print("\n" + "▒" * 40 + "\n CONFIGURARE SWITCH-URI\n" + "▒" * 40)
        for i, sw in enumerate(switch_configs):
            print(f"\n>>> SWITCH #{i+1} ({sw['net']})"); print("-" * 50)
            print("enable"); print("conf t"); print("interface vlan 1"); print(f"ip address {sw['ip']} {sw['mask']}")
            print("no shutdown"); print("exit"); print(f"ip default-gateway {sw['gw']}"); print("exit"); print("-" * 50)
    if pc_configs:
        print("\n" + "▓" * 40 + "\n CONFIGURARE PC-URI\n" + "▓" * 40)
        for i in pc_configs: print(f"[{i['net']}] IP: {i['ip']} | Mask: {i['mask']} | GW: {i['gw']}")

# ==============================================================================
#                 OPȚIUNEA 14: DEBUG & RESET MENU
# ==============================================================================

def debug_and_reset():
    while True:
        print("\n" + "!" * 60)
        print("          MENIU DEBUG & RESET (URGENȚE)")
        print("!" * 60)
        print("1.  Generare comenzi SHOW (Diagnostic complet)")
        print("2.  Șterge IP de pe o interfață (No IP Address)")
        print("3.  Șterge o Rută (No IP Route)")
        print("4.  Șterge tabela MAC (Clear Mac-Address-Table)")
        print("5.  Șterge tabela ARP (Clear ARP)")
        print("6.  Resetare Interfață (Shutdown + No IP)")
        print("0.  Înapoi la meniul principal")
        opt = input("\n>> DEBUG OPT: ")
        if opt == '0': break
        elif opt == '1':
            print_header("COMENZI DIAGNOSTIC")
            print("do show ip interface brief")
            print("do show ip route")
            print("do show vlan brief")
            print("do show interfaces trunk")
            print("do show running-config")
        elif opt == '2':
            iface = input("Interfața: "); print_commands([f"interface {iface}", "no ip address", "no shutdown", "exit"])
        elif opt == '3':
            dest = input("Rețea: "); mask = cidr_to_mask(input("Masca: ")); hop = input("Next Hop: ")
            print_commands([f"no ip route {dest} {mask} {hop}"])
        elif opt == '4': print_commands(["do clear mac-address-table dynamic"])
        elif opt == '5': print_commands(["do clear arp-cache"])
        elif opt == '6':
            iface = input("Interfața: "); print_commands([f"interface {iface}", "shutdown", "no ip address", "exit"])

# ==============================================================================
#                 OPȚIUNEA 15: REZOLVARE DE ERORI (TROUBLESHOOTING)
# ==============================================================================

def troubleshooting_guide():
    print_header("15. GHID REZOLVARE ERORI (EXAMEN)")
    print("Aici sunt cele mai frecvente capcane din examen și cum le rezolvi.")
    print("-" * 70)
    
    print("\n[SCENARIUL 1] O interfață este oprită (ROSU pe link)")
    print("   -> Cauză: Cineva a dat 'shutdown' pe port.")
    print("   -> Rezolvare: Switch(config)# interface fa0/1 -> no shutdown")
    print("   -> REZOLVARE RAPIDĂ DIN SCRIPT: Folosește Opțiunea 1 (Config IP).")
    
    print("\n[SCENARIUL 2] VLAN-ul nu trece prin Trunk")
    print("   -> Simptom: Ping nu merge între switch-uri, deși link-ul e verde.")
    print("   -> Cauză: 'allowed vlan' restricționează traficul.")
    print("   -> Verificare: do show interfaces trunk")
    print("   -> REZOLVARE RAPIDĂ DIN SCRIPT: Folosește Opțiunea 3 (TRUNK) și scrie 'all' la VLAN-uri.")
    
    print("\n[SCENARIUL 3] Rutare greșită (Pachetele se pierd)")
    print("   -> Simptom: Ping la un IP extern dă 'Request Timed Out'.")
    print("   -> Cauză: Ruta statică e scrisă greșit.")
    print("   -> Verificare: do show ip route")
    print("   -> REZOLVARE RAPIDĂ DIN SCRIPT: Folosește Opțiunea 14 -> 3 (Șterge Rută), apoi Opțiunea 4 (Rută Statică).")
    
    print("\n[SCENARIUL 4] PC-ul nu are net")
    print("   -> Cauză: Default Gateway lipsește sau e greșit pe PC.")
    print("   -> Verificare: Folosește Opțiunea 10 (Comenzi PC) -> ipconfig")
    print("   -> REZOLVARE: Folosește Opțiunea 12/13 ca să afli IP-ul corect de Gateway.")
    
    print("\n[SCENARIUL 5] Router-on-a-Stick nu merge")
    print("   -> Cauză: Interfața fizică a routerului e 'shutdown' sau nu are IP pe subinterfețe.")
    print("   -> REZOLVARE RAPIDĂ DIN SCRIPT: Folosește Opțiunea 12 sau 13 și specifică 'da' la subinterfață.")
    
    input("\n[Apasă Enter pentru a reveni la meniu]")

# ==============================================================================
#                                   MENIU PRINCIPAL
# ==============================================================================

def meniu():
    while True:
        print("\n" + "*"*70)
        print("      SCRIPT EXAMEN PACKET TRACER (V21 - THE NAVIGATOR)")
        print("*"*70)
        print("1.  Configurare IP Router/SVI (Detectare Serial)")
        print("2.  VLAN & Porturi Access")
        print("3.  TRUNK (Allowed VLANs)")
        print("4.  Rută Statică")
        print("5.  Rută Default")
        print("6.  Securitate Management")
        print("7.  DHCP Pool")
        print("8.  STP Priority")
        print("9.  Static MAC")
        print("10. Comenzi Utile PC & DEBLOCARE CONSOLĂ")
        print("-" * 70)
        print("11. AUTO-TOPOLOGY  [Calculează VLSM de la zero]")
        print("12. SMART CONFIG   [Am CIDR-ul -> Tu pui IP-urile automat]")
        print("13. MANUAL TOTAL   [Eu scriu IP-ul la fiecare device]")
        print("-" * 70)
        print("14. >> DEBUG & RESET [Show, Clear, Delete]")
        print("15. >> REZOLVARE DE ERORI [Ghid + Scurtături]")
        print("-" * 70)
        print("0.  Ieșire")
        
        opt = input("\n>> Alege numărul opțiunii: ")
        
        if opt == '11': auto_topology_generator()
        elif opt == '12': smart_manual_generator()
        elif opt == '13': full_manual_generator()
        elif opt == '14': debug_and_reset()
        elif opt == '15': troubleshooting_guide()
        elif opt == '0': break
        elif opt == '1': config_interfata_ip()
        elif opt == '2': config_vlan_access()
        elif opt == '3': config_trunk()
        elif opt == '4': config_static_route()
        elif opt == '5': config_default_route()
        elif opt == '6': config_management_ssh()
        elif opt == '7': config_dhcp_server()
        elif opt == '8': config_stp_priority()
        elif opt == '9': config_static_mac()
        elif opt == '10': cheat_pc()
        else: print("!!! Opțiune greșită.")

if __name__ == "__main__":
    meniu()