from scapy.all import sniff

print("Start checking traffic on possible ARP attacks...\n")

# Словарь, имитирующий ARP-таблицу
IP_MAC_Map = {}

# Функция принимает пакет, в этом случае arp
def processPacket(packet):
	src_IP = packet['ARP'].psrc # айпи того, кто послал кого арп-ответ
	src_MAC = packet['Ether'].src # его мак адрес
	if src_MAC in IP_MAC_Map.keys():
		if IP_MAC_Map[src_MAC] != src_IP : # Если айпи адрес отправителя из таблицы не совпадает с его "новым" айпи
			try:
				old_IP = IP_MAC_Map[src_MAC] # То достаем его старый айпи
			except:
				old_IP = "unknown"
			message = ("\n Possible ARP attack detected \n "
				+ "It is possible that the machine with real IP address \n "
				+ str(old_IP) + " is pretending to be " + str(src_IP)
				+ "\n ")
			return message
	else:
		IP_MAC_Map[src_MAC] = src_IP # Если устройство нет в таблице, то вносим его

# Библиотека для перехватка и проверки траффика по функции prn; count - количество проверяемых пакетов(0-все); store - сколько пакетов хранить		
sniff(count=0, filter="arp", store = 0, prn = processPacket)
