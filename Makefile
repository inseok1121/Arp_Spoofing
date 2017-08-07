all : arp

arp : main.cpp
	gcc -o arp main.cpp -lpcap -I/usr/include/pcap -W -Wall -pthread

clean:
	rm -f arp
