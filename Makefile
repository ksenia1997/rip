all: myripsniffer myripresponse

myripsniffer: ripsniffer.o
	g++ ripsniffer.o -lpcap -o myripsniffer

myripresponse: ripresponse.o ripngpacket.o
	g++ ripresponse.o ripngpacket.o -o myripresponse -g
ripsniffer.o: ripsniffer.cpp
	g++ -std=c++11  ripsniffer.cpp -c

ripresponse.o: ripresponse.cpp ripngpacket.h
	g++ -std=c++11 -c ripresponse.cpp -g

ripngpacket.o: ripngpacket.cpp ripngpacket.h
	g++ -std=c++11 -c ripngpacket.cpp -g
clean:
	rm -rf *o myripsniffer myripresponse
