all:
	g++ -std=c++17 -pthread -Wno-deprecated-declarations client.cpp -o client \
	-I$(shell brew --prefix openssl@3)/include \
	-L$(shell brew --prefix openssl@3)/lib -lssl -lcrypto

clean:
	rm -f client