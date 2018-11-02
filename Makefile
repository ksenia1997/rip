all: myripsniffer myripresponse

myripsniffer: ripsniffer.o
	g++ ripsniffer.o -lpcap -o myripsniffer

myripresponse: ripresponse.o ripngheader.o
	g++ ripresponse.o ripngheader.o -o myripresponse
ripsniffer.o: ripsniffer.cpp
	g++ -std=c++11  ripsniffer.cpp -c

ripresponse.o: ripresponse.cpp ripngheader.h
	g++ -std=c++11 -c ripresponse.cpp

ripngheader.o: ripngheader.cpp ripngheader.h
	g++ -std=c++11 -c ripngheader.cpp
clean:
	rm -rf *o myripsniffer myripresponse
