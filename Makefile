all: myripsniffer

myripsniffer: isa.o
	g++ isa.o -lpcap -o myripsniffer

isa.o: isa.cpp
	g++ -c isa.cpp

clean:
	rm -rf *o myripsniffer
