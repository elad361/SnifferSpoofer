all: ping watchdog sniffer spoofer
sniffer: sniffer.c
	gcc sniffer.c -o sniffer -lpcap
spoofer: spoofer.c
	gcc spoofer.c -o spoofer -lpcap 
watchdog: watchdog.c
	gcc watchdog.c -o watchdog
ping: ping.c
	gcc ping.c -o ping

clean:
	rm -f *.o watchdog partb sniffer spoofer
