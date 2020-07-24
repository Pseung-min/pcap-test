all: pcap-test

pcap-test: main.o
	g++ -o pcap-test main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f pcap-test main.o


