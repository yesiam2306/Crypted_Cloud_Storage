#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include "server_commands.cpp"
#include "session_authentication.cpp"
using namespace std;


int main(int argc, char* argv[]){

	int port = 4243;
	srand(time(NULL));
	uint32_t counter_server = rand()%INT_MAX;
	uint32_t counter_client;
	int ret, sd, len, sd_client, length;
	struct sockaddr_in my_addr, cl_addr;
	pid_t pid;
	uint16_t lmsg;
	unsigned char* buffer;

	/* Socket creation */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd < 0)
		perror("Error occurred when creating the socket\n");
	else
		printf("Socket successfully created\n");

	/* Assigning a socket to an address */
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	/* Socket connection */
	ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret < 0){
		perror("Error occurred during the bind: \n");
		exit(-1);
	}
	else
		printf("Bind has been successfull.\n");

	ret = listen(sd, 10);
	if(ret < 0){
		perror("Error occurred during the listen.\n");
		exit(-1);
	}
	else
		printf("Listen has been successfull.\n");


	while(1) {

		length = sizeof(cl_addr);
		len = ntohs(length);

		/* The server accepts new connections */
		sd_client = accept(sd, (struct sockaddr*)&cl_addr, (socklen_t*)&len);
		if(sd_client < 0) {
		  perror("Error occurred during the accept:\n");
		  exit(-1);
		}
		else {
		  printf("Accept has been successfull. The client address is: %s\n", inet_ntoa(cl_addr.sin_addr));
		}

		/* Creazione processo figlio */
		pid = fork();

		if(pid < 0)
			printf("Error occured: child process not created");
			
		else if(pid == 0) {
			// processo figlio
			
			close(sd);
			
			// keys and username
			EVP_PKEY* client_public_key = NULL;
			EVP_PKEY* server_private_key = NULL;
			EVP_PKEY* ephemeral_private_key = NULL;
			EVP_PKEY* ephemeral_public_key = NULL; 
			string username_s;
			
			// first msg
			int user_len = receive_first_message(sd_client, counter_client, client_public_key, username_s);
			
			unsigned char* user = (unsigned char*)malloc((user_len+1) * sizeof(unsigned char));
			memcpy(user, &username_s[0], user_len);
			user[user_len] = '\0';
			
			// second msg
			send_second_message(sd_client, counter_server, counter_client, server_private_key, ephemeral_private_key, ephemeral_public_key);
			
			unsigned char* symmetric_key = (unsigned char*)malloc((16+1) * sizeof(unsigned char));
			
			// third msg
			symmetric_key = receive_third_message(sd_client, counter_client, counter_server, client_public_key, ephemeral_private_key);
			symmetric_key[16] = '\0';
			
			// delete the ephemeral keys
			EVP_PKEY_free(ephemeral_public_key);
			EVP_PKEY_free(ephemeral_private_key);
			
			// release the client public key and the server private key
			EVP_PKEY_free(client_public_key);
			EVP_PKEY_free(server_private_key);
			
			counter_server = 0;
			counter_client = 0;
//----------------------------------------------------------------------------------------------------------------------
			
			while(1) {
				unsigned char* cmd = NULL;
				cmd = receive_cipher(sd_client, buffer, counter_client, symmetric_key);
				if(!cmd) {
					cout << "Error occurred: receive failed" << endl << "Waiting for a command..." << endl;
					continue;
				}
				
				cmd[strlen((const char*)cmd)] = '\0';
				string command(reinterpret_cast<char const*>(cmd), strlen((const char*)cmd));
				
				if(command == "<error>") {
					cout << "Error occurred on client side" << endl << "Waiting for a command..." << endl;
					continue;
				}
				
				if(command.size() > 8) {
					cout << "Error occurred: too many characters (max 8)" << endl << "Waiting for a command..." << endl;
					string error = "<error_size>";
					int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
					if(ret < 0) {
						cout << "Error occurred: send failed" << endl << "Waiting for a command..." << endl;
						continue;
					}
					continue;
				}
	
				if(!check_input(command)) {
					cout << "Error occurred: wrong filename format" << endl << "Waiting for a command..." << endl;
					string error = "<error_format>";
					int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
					if(ret < 0) {
						cout << "Error occurred: send failed" << endl << "Waiting for a command... " << endl;
						continue;
					}
					continue;
				}
				else {
					string confirm = "<ok>";
					int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
					if(ret < 0) {
						cout << "Error occurred: send failed" << endl << "Waiting for a command..." << endl;
						continue;
					}
				}
				
				
				if(command == "List") {
					cout << "Command received" << endl;
					list(sd_client, counter_server, symmetric_key, user, user_len);
					cout << "Waiting for a command..." << endl;
					continue;
				}
				
				if(command ==  "Upload") {
					cout << "Command received" << endl;
					upload(sd_client, counter_client, counter_server, symmetric_key, user, user_len);
					cout << "Waiting for a command..." << endl;
					continue;
				}
				
				if(command == "Download") {
					cout << "Command received" << endl;
					download(sd_client, counter_server, counter_client, symmetric_key, user, user_len);
					cout << "Waiting for a command..." << endl;
					continue;
				}
				
				if(command == "Delete") {
					cout << "Command received" << endl;
					Delete(sd_client, counter_client, counter_server, symmetric_key, user, user_len);
					cout << "Waiting for a command..." << endl;
					continue;
				}
				
				if(command == "Rename") {
					cout << "Command received" << endl;
					ret = Rename(sd_client, counter_client, counter_server, symmetric_key, user, user_len);
					cout << "Waiting for a command..." << endl;
					continue;
				}
				
				if(command == "LogOut") {
					cout << "Command received" << endl; 
					log_out(sd_client, counter_server, symmetric_key);
					cout << "Waiting for a command..." << endl;
					continue;
				}
			}
			ret = close(sd_client);
			free(symmetric_key);
		}
		else {
			ret = close(sd_client);
		}  
	}
	
	return 0;
}

