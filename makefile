#https://web.eecs.umich.edu/~sugih/pointers/make.html
server client: server.o client.o
	g++ -Wall server.o -o server -lcrypto
	g++ -Wall client.o -o client -lcrypto

server.o: server.cpp
	g++ -g -c server.cpp -lcrypto

client.o: client.cpp
	g++ -g -c client.cpp -lcrypto

clean:
	rm *.o
