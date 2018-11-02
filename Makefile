all: myripsniffer myripresponse

myripsniffer: ripsniffer.o
	g++ ripsniffer.o -lpcap -o myripsniffer

myripresponse: ripresponse.o
	g++ ripresponse.o -o myripresponse
ripsniffer.o: ripsniffer.cpp
	g++ -std=c++11  ripsniffer.cpp -c

ripresponse.o: ripresponse.cpp ripngheader.h
	g++ -std=c++11 -c ripresponse.cpp


clean:
	rm -rf *o myripsniffer myripresponse
