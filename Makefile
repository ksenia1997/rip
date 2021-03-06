all: myripsniffer myripresponse myriprequest

myripsniffer: ripsniffer.o
	g++ ripsniffer.o -lpcap -o myripsniffer

myripresponse: ripresponse.o ripngpacket.o
	g++ ripresponse.o ripngpacket.o -o myripresponse 

myriprequest: riprequest.o ripngpacket.o
	g++ riprequest.o ripngpacket.o -o myriprequest

ripsniffer.o: ripsniffer.cpp
	g++ -std=c++11  ripsniffer.cpp -c

ripresponse.o: ripresponse.cpp ripngpacket.h
	g++ -std=c++11 -c ripresponse.cpp 
riprequest.o: riprequest.cpp ripngpacket.h
	g++ -std=c++11 -c riprequest.cpp 

ripngpacket.o: ripngpacket.cpp ripngpacket.h
	g++ -std=c++11 -c ripngpacket.cpp 
clean:
	rm -rf *o myripsniffer myripresponse myriprequest
