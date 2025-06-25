from scapy.layers.all import IP, TCP
from scapy.all import *
import socket



list_ports = [21, 22, 43, 40, 65, 80, 443, 445]

best_ports = [20, 21, 22, 23, 25, 53, 80, 102, 110, 119, 135, 137, 138, 139, 143, 389, 443, 445, 554, 636, 993, 995, 1214, 1433, 1434, 1617, 1755, 1863, 3306, 3112, 3185, 3389, 3700, 4000, 4661, 4662, 4665, 4848, 5050, 5060, 5190, 5985, 6346, 6347, 7070, 7071, 7676, 8009, 8020, 8027, 8080, 8181, 8383, 8484, 8585, 8686, 9200, 9300]

total_ports = [1, 2, 3, 4, 10, 20, 21, 22, 25, 30, 33, 36, 40, 80, 443]

portas_abertas = []
portas_fechadas = []


print(
    "Seja bem-vindo ao programa\n"
    "By: KENSH1K\n"

)



def service(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        s.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode("utf-8") + b'\r\n\r\n')
        return s.recv(1024)
    except:
        return None


def scanner(ip, port):
    ip_pkt = IP(dst=ip)
    tcp_pkt = TCP(dport=port, flags="S")

    pkt = ip_pkt / tcp_pkt

    resp = sr1(pkt, timeout=2, verbose=0)


    if resp is not None:
        if resp.haslayer(TCP):

            if resp.getlayer(TCP).flags == 0x12:
                portas_abertas.append(port)
                return True
            elif resp.getlayer(TCP).flags == 0x14:
                return False
    return False




def sniffer_wifi():
    print("iniciando o sniffer...")
    sniff(iface="Wi-Fi", filter=filtro, prn=lambda packet: print(packet.show))

def sniffer_eth0():
    print("iniciando o sniffer...")
    sniff(iface="eth0", filter="icmp", prn=lambda packet: print(packet.show))

def sniffer_eth1():
    print("iniciando o sniffer...")
    sniff(iface="eth1", filter="icmp", prn=lambda packet: print(packet.show))



while True:
    try:
        print("selecione uma opção:\n[1] scan de portas\n[2] sniffer\n[3] opção\n[4] fechar o programa\n")
        scan_type = int(input("digite a opção: "))

        if scan_type == 1:
            try:
                ip = input("digite o ip do alvo: ")
                print("[1] ports range 20-10000  [2] principais 4 portas  [3] todas as portas 1-65535 ")
                portas = int(input("digite uma opção: "))


                if portas == 1:
                    servs = input("gostaria de scan relacionado com os serviços, s ou n ? ")
                    print("iniciando o scan...")
                    if servs == "n":
                        for port in best_ports:
                            scanner(ip, port)

                    elif servs == "s":
                        for port in best_ports:
                            status = scanner(ip, port)
                            if status:
                                banner = service(ip, port)
                                if banner:
                                    banner = banner.split(b'\r\n')[0]
                                    print(f"porta: {port} aberta", banner.decode("utf-8"))

                                else:
                                    continue
                            else:
                                continue

                    else:
                        print("erro")


                elif portas == 2:
                    servs = input("gostaria de scan relacionado com os serviços, s ou n ? ")
                    print("iniciando o scan...")
                    if servs == "n":
                        for port in list_ports:
                            scanner(ip, port)

                    elif servs == "s":
                        for port in list_ports:
                            status = scanner(ip, port)
                            if status:
                                banner = service(ip, port)
                                if banner:
                                    banner = banner.split(b'\r\n')[0]
                                    print(f"porta: {port} aberta", banner.decode("utf-8"))

                                else:
                                    continue
                            else:
                                continue




                    else:
                        print("erro")



                elif portas == 3:
                    servs = input("gostaria de scan relacionado com os serviços, s ou n ? ")
                    print("iniciando o scan...")
                    if servs == "n":
                        for port in range(1, 65535):
                            scanner(ip, port)

                    elif servs == "s":
                        for port in range(20, 500):
                            status = scanner(ip, port)
                            if status:
                                banner = service(ip, port)
                                if banner:
                                    banner = banner.split(b'\r\n')[0]
                                    print(f"porta: {port} aberta", banner.decode("utf-8"))

                                else:
                                    continue
                            else:
                                continue



                else:
                    print("digite uma opção valida")

                print("\nportas abertas", portas_abertas)

            except:

                print("erro ao realizar o scan, verifique a conexao com a internet")


        elif scan_type == 2:
            try:
                print("[1] Placa Wi-Fi  [2] eth0  [3] eth1")
                rede = int(input("digite qual placa de rede gostaria de sniffar: "))
                print("\n[1] tcp  [2] udp  [3] icmp")
                proto = int(input("digite uma opção: "))


                if rede == 1:
                    if proto == 1:
                        filtro = "tcp"
                    elif proto == 2:
                        filtro = "udp"
                    elif proto == 3:
                        filtro = "icmp"
                    sniffer_wifi()


                elif rede == 2:
                    if proto == 1:
                        filtro = "tcp"
                    elif proto == 2:
                        filtro = "udp"
                    elif proto == 3:
                        filtro = "icmp"
                    sniffer_eth0()


                elif rede == 3:
                    if proto == 1:
                        filtro = "tcp"
                    elif proto == 2:
                        filtro = "udp"
                    elif proto == 3:
                        filtro = "icmp"
                    sniffer_eth1()

            except:
                print("erro ao realizar o sniffer, tente selecionar outra placa de rede")

        elif scan_type == 3:
            try:
                print("algum erro")

            except:
                print("")

        elif scan_type == 4:
            print("bye bye :)")
            break

        else:
            print("opção inválida")
    except:
        print("opção inválida")
