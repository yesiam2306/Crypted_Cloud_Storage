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
#include "client_commands.cpp"
#include "session_authentication.cpp"
using namespace std;

int main(int argc, char* argv[]){

	int port = 4243;
	srand(time(NULL));
	uint32_t counter_client = rand()%INT_MAX;
	uint32_t counter_server;
	const char* server_address = "127.0.0.1";
	int ret, sd, len, cfor;
	bool command_found;  /* controlla che è stato trovato un comando */
	uint16_t lmsg;
	struct sockaddr_in srv_addr;
	
	/* Socket creation */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("Error occurred during the socket creation\n");
		exit(-1);
	}
	else
  		printf("Socket successfully created\n");

	/* Address creation */
	memset(&srv_addr, 0, sizeof(srv_addr)); /* clean */
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	inet_pton(AF_INET, server_address, &srv_addr.sin_addr);

	/* Connection to the server */
	ret = connect(sd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	// printf("%d\n", ret);
	if(ret < 0) {
		perror("Error occurred during the connect: \n");
		exit(-1);
	}
	else
  		printf("Client connected\n\n");

	// keys
	EVP_PKEY* client_private_key = NULL;
	EVP_PKEY* server_public_key = NULL;
	EVP_PKEY* ephemeral_public_key = NULL;
	
	// first msg
	send_first_message(sd, counter_client, client_private_key);
	
	// second msg
	ephemeral_public_key = receive_second_message(sd, counter_server, counter_client, server_public_key);
	
	unsigned char* symmetric_key = (unsigned char*)malloc((16+1) * sizeof(unsigned char));
	
	// third msg
	symmetric_key = send_third_message(sd, counter_client, counter_server, ephemeral_public_key, client_private_key);
	symmetric_key[16] = '\0';
	
	// delete the ephemeral key
	EVP_PKEY_free(ephemeral_public_key);
	
	// release the client private key and the server public key
	EVP_PKEY_free(client_private_key);
	EVP_PKEY_free(server_public_key);

	counter_client = 0;
	counter_server = 0;
//------------------------------------------------------------------------

	  
	printf("\n********Welcome********\n\nThe following commands are available:\n1)Upload --> it loads a file\n2)Download --> it downloads a file\n3)Delete --> it removes a file\n4)List --> it lists the filenames of the available files in the storage\n5)Rename --> it allows to change the name of a chosen filename\n6)LogOut --> it closes the connection\n\n");

	command_found = false;
	bool first_command = true;
	while(1) {
		string command;
		
		if(!command_found) {
			if(first_command) {
				printf("Insert a command: ");
				first_command = false;
			}
			else
				printf("Insert a valid command please: ");
		}
		else {
			command_found = false;
			continue;
		}
		
		/* Command */
		getline(cin, command);
		if(!cin) {
			// handle errors
			cout << "Error occurred: invalid input" << endl;
			string confirm = "<error>";
			ret = send_cipher(sd, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				continue;
			}
			continue;
		}
		
		ret = send_cipher(sd, (unsigned char*)command.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			continue;
		}
		
		unsigned char* buf;
		unsigned char* format = NULL;
		format = receive_cipher(sd, buf, counter_server, symmetric_key);
		if(!format) {
			cout << "Error occurred: receive failed" << endl;
			continue;
		}
		format[strlen((const char*)format)] = '\0';
	
		if(strcmp((const char*)format, "<error_size>") == 0) {
			cout << "Error occurred: too many characters (max 8)" << endl;
			continue;
		}
	
		if(strcmp((const char*)format, "<error_format>") == 0) {
			cout << "Error occurred: wrong filename format! You can only use a:z A:Z 1234567890-.\'@" << endl;
			continue;
		}
		
		// search for some command
		
		if(command == "Help") {
			command_found = true;
			first_command = true;
			printf("\n\nThe following commands are available:\n1)Upload --> it loads a file\n2)Download --> it downloads a file\n3)Delete --> it removes a file\n4)List --> it lists the filenames of the available files in the storage\n5)Rename --> it allows to change the name of a chosen filename\n6)LogOut --> it closes the connection\n7)Help --> it shows the valid commands\n\n");
			continue;
		}
	
			
		if(command == "List") {
			command_found = true;
			first_command = true;
			list(sd, counter_server, symmetric_key);
			continue;
		}
			
		if(command == "Upload") {
			command_found = true;
			first_command = true;
			upload(sd, counter_client, counter_server, symmetric_key);
			continue;
		}
		
		if(command == "Download") {
			command_found = true;
			first_command = true;
			download(sd, counter_server, counter_client, symmetric_key);
			continue;
		}
		
		if(command == "Delete") {
			command_found = true;
			first_command = true;
			Delete(sd, counter_client, counter_server, symmetric_key);
			continue;
		}
		
		if(command == "Rename") {
			command_found = true;
			first_command = true;
			ret = Rename(sd, counter_client, counter_server, symmetric_key);
			continue;
		}
			
		if(command == "LogOut") {
			command_found = true;
			first_command = true;
				
			ret = log_out(sd, counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred. Please retry." << endl;
				continue;
			}
			else {
				free(symmetric_key);
				exit(0);
			}
		}
	}
	
	free(symmetric_key);
	close(sd);
	  
	return 0;
	
}
