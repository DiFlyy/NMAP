import nmap
import os

def scan_network(hosts, ports, arguments, super_user):
    nm = nmap.PortScanner()
    nm.scan(hosts=hosts, ports=ports, arguments=arguments, sudo=super_user)

    print("Escaneo completo: ")
    for host in nm.all_hosts():
        print("Host: ", host)
        print("Estado: ", nm[host].state())
        for proto in nm[host].all_protocols():
            print("Protocolo: ", proto)
            ports = nm[host][proto].keys()
            for port in ports:
                print("Puerto: ", port, "Estado: ", nm[host][proto], "\n")

if __name__ == "__main__":
    hosts = input("Ingrese los hosts (separados por comas): ").strip()
    ports = input("Ingrese los puertos (separados por comas): ").strip()
    arguments = input("Ingrese los argumentos de nmap: ").strip()
    super_user_input = input("Ejecutar como super usuario? (si/no): ").strip().lower()

    super_user = True if super_user_input == "si" else False

    scan_network(hosts,ports,arguments,super_user)