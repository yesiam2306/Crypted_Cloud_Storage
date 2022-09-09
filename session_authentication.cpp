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
using namespace std;

// *********** SERVER MESSAGES *************

int receive_first_message(int sd_client, uint32_t &nonce_client, EVP_PKEY* &public_key, string &username_s) {
	
	char* first_msg;
	uint16_t first_msg_len;
	int ret = receive_response(sd_client, first_msg, first_msg_len);
	
	// nonce_client
	int nonce_client_len = first_msg[0];
	
	unsigned char* nonce_client_uc = (unsigned char*)malloc((nonce_client_len+1) * sizeof(unsigned char));
	memcpy(nonce_client_uc, &first_msg[1], nonce_client_len);
	nonce_client_uc[nonce_client_len] = '\0';
	
	// cert_client
	int cert_client_size_uc_len = first_msg[1 + nonce_client_len];
	
	unsigned char* cert_client_size_uc = (unsigned char*)malloc((cert_client_size_uc_len + 1) * sizeof(unsigned char));
	memcpy(cert_client_size_uc, &first_msg[2 + nonce_client_len], cert_client_size_uc_len);
	cert_client_size_uc[cert_client_size_uc_len] = '\0';			
	long int cert_client_size = atol((const char*)cert_client_size_uc);

	unsigned char* cert_client_uc = (unsigned char*)malloc((cert_client_size + 1) * sizeof(unsigned char));
	memcpy(cert_client_uc, &first_msg[2 + nonce_client_len + cert_client_size_uc_len], cert_client_size);
	cert_client_uc[cert_client_size] = '\0';
	X509* cert_client = deserialize_cert(cert_client_uc, cert_client_size);
	
	// user
	int user_len = first_msg[2 + nonce_client_len + cert_client_size_uc_len + cert_client_size];
	
	unsigned char* user = (unsigned char*)malloc((user_len+1) * sizeof(unsigned char));
	memcpy(user, &first_msg[3 + nonce_client_len + cert_client_size_uc_len + cert_client_size], user_len);
	user[user_len] = '\0';
	if(user_len >  20) {
		cout << "Error occurred: too many characters(max 20 characters)" << endl;
		exit(1);
	}
	string username(reinterpret_cast<char const*>(user), user_len);
	if(!check_input(username)) {
		cout << "Error occurred: wrong username format! You can only use a:z A:Z 1234567890-.\'@" << endl;
		exit(1);
	}
	

	
	// load client public key
	string long_term_public_file;
	username_s = username;
	long_term_public_file = "./Server/" + username + "_public_key.pem";
	FILE* public_key_file = fopen((const char*)long_term_public_file.c_str(), "r");
	if(!public_key_file) {
		cout << "public_key not found!" << endl;
		exit(1);
	}
	public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
	fclose(public_key_file);
	
	// verify if the cert is correct
	EVP_PKEY* public_key_cert_client = X509_get_pubkey(cert_client);
	int res = EVP_PKEY_cmp(public_key_cert_client, public_key);
	if(res == 0) {
		cout << "***WARNING***" << endl << "public keys dont match!" << endl;
		exit(1);
	}
	if(res == -1) {
		cout << "key types are different" << endl;
		exit(1);
	}
	
	nonce_client = atol((const char*)nonce_client_uc);
	
	X509_STORE* cert_store = NULL;
	init_cert_store_server(cert_store);
	verify_cert_received(cert_store, cert_client);
	
	
	free(nonce_client_uc);
	free(user);
	
	return user_len;
	
}

void send_second_message (int sd_client, uint32_t nonce_server, uint32_t nonce_client, EVP_PKEY* &private_key, EVP_PKEY* &ephemeral_private_key, EVP_PKEY* &ephemeral_public_key) {

	// cert_server
	long int my_cert_size;
	unsigned char* my_cert = get_cert(my_cert_size);
	my_cert[my_cert_size] = '\0';	
	
	// nonce_client
	string aux = to_string(nonce_client);
	int nonce_client_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_client_uc = (unsigned char*)malloc((nonce_client_len+1) * sizeof(unsigned char));
	memcpy(&nonce_client_uc[0], aux.c_str(), nonce_client_len);
	nonce_client_uc[nonce_client_len] = '\0';
	
	// nonce_server
	aux = to_string(nonce_server);
	int nonce_server_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_server_uc = (unsigned char*)malloc((nonce_server_len+1) * sizeof(unsigned char));
	memcpy(&nonce_server_uc[0], aux.c_str(), nonce_server_len);
	nonce_server_uc[nonce_server_len] = '\0';

	// generate ephemeral keys
	generate_ephemeral_keys(&ephemeral_private_key, &ephemeral_public_key);
	if(ephemeral_private_key == NULL || ephemeral_public_key == NULL){
		cout << "Error occurred in generating the keys" << endl;
		exit(1);
	}
	int eph_pub_key_len;
	unsigned char* eph_public_key = serialize_public_key(ephemeral_public_key, eph_pub_key_len);
	
	// generate the plainext to sign
	int plaintext_len = nonce_client_len + nonce_server_len + eph_pub_key_len;
	char* plaintext = (char*)malloc((plaintext_len+1) * sizeof(char));
	memcpy(&plaintext[0], nonce_client_uc, nonce_client_len);
	memcpy(&plaintext[nonce_client_len], nonce_server_uc, nonce_server_len);
	memcpy(&plaintext[nonce_client_len + nonce_server_len], eph_public_key, eph_pub_key_len);
	plaintext[plaintext_len] = '\0';
	
	
	string long_term_private_file; 
	
	long_term_private_file = "./Server/server_key.pem";
	
	// load the server private key
	FILE* private_key_file = fopen((const char*)long_term_private_file.c_str(), "r");
	if(!private_key_file) {
		cout << "Error! Private key file not found!" << endl;
		exit(1);
	}	
	private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
	fclose(private_key_file);
	if(!private_key) {
		cout << "Error during the digit of the password, retry. (In this example of project the password is \"studenti\")." << endl;
		exit(1);
	}
	
	// signature
	int signature_len = EVP_PKEY_size(private_key);
	unsigned char* signature = (unsigned char*)malloc((signature_len+1) * sizeof(unsigned char));
	
	signature_len = dig_sign_sgn((unsigned char*)plaintext, plaintext_len, private_key, (unsigned char*)signature);
	signature[signature_len] = '\0';
	
	unsigned char* signature_len_uc = (unsigned char*)malloc((to_string(signature_len).size()+1) * sizeof(unsigned char));
	signature_len_uc = (unsigned char*)to_string(signature_len).c_str();
	signature_len_uc[to_string(signature_len).size()] = '\0';
	int signature_len_uc_len = strlen((const char*)signature_len_uc);
	
	// ephimeral public key
	unsigned char* eph_public_key_len_uc = (unsigned char*)malloc((to_string(eph_pub_key_len).size()+1) * sizeof(unsigned char));
	eph_public_key_len_uc = (unsigned char*)to_string(eph_pub_key_len).c_str();
	eph_public_key_len_uc[to_string(eph_pub_key_len).size()] = '\0';
	int eph_pub_key_len_uc_len = strlen((const char*)eph_public_key_len_uc);
	
	// server_cert
	unsigned char* my_cert_size_uc = (unsigned char*)malloc((to_string(my_cert_size).size()+1) * sizeof(unsigned char));
	my_cert_size_uc = (unsigned char*)to_string(my_cert_size).c_str();
	my_cert_size_uc[to_string(my_cert_size).size()] = '\0';
	int my_cert_size_uc_len = strlen((const char*)my_cert_size_uc);		
	
	// second msg
	int second_msg_len = 1 + nonce_server_len + 1 + my_cert_size_uc_len + my_cert_size + 1 + eph_pub_key_len_uc_len + eph_pub_key_len + 1 + signature_len_uc_len + signature_len;
	char* second_msg = (char*)malloc((second_msg_len+1) * sizeof(char));
	
	// nonce_server
	memcpy(&second_msg[0], &nonce_server_len, 1);
	memcpy(&second_msg[1], nonce_server_uc, nonce_server_len);
	
	// server cert
	memcpy(&second_msg[1 + nonce_server_len], &my_cert_size_uc_len, 1);
	memcpy(&second_msg[2 + nonce_server_len], my_cert_size_uc, my_cert_size_uc_len);
	memcpy(&second_msg[2 + nonce_server_len + my_cert_size_uc_len], my_cert, my_cert_size);
	
	// eph_pub_key
	memcpy(&second_msg[2 + nonce_server_len + my_cert_size_uc_len + my_cert_size], &eph_pub_key_len_uc_len, 1);
	memcpy(&second_msg[3 + nonce_server_len + my_cert_size_uc_len + my_cert_size], eph_public_key_len_uc, eph_pub_key_len_uc_len);
	memcpy(&second_msg[3 + nonce_server_len + my_cert_size_uc_len + my_cert_size + eph_pub_key_len_uc_len], eph_public_key, eph_pub_key_len);
	
	// signature
	memcpy(&second_msg[3 + nonce_server_len + my_cert_size_uc_len + my_cert_size + eph_pub_key_len_uc_len + eph_pub_key_len], &signature_len_uc_len, 1);
	memcpy(&second_msg[4 + nonce_server_len + my_cert_size_uc_len + my_cert_size + eph_pub_key_len_uc_len + eph_pub_key_len], signature_len_uc, signature_len_uc_len);
	memcpy(&second_msg[4 + nonce_server_len + my_cert_size_uc_len + my_cert_size + eph_pub_key_len_uc_len + eph_pub_key_len + signature_len_uc_len], signature, signature_len);
	
	second_msg[second_msg_len] = '\0';
	
	int ret = send_response(sd_client, (unsigned char*)second_msg, second_msg_len);

}

unsigned char* receive_third_message(int sd_client, uint32_t &nonce_client, uint32_t nonce_server, EVP_PKEY* public_key, EVP_PKEY* &ephemeral_private_key) {

	uint16_t third_msg_len;
	char* third_msg;

	int ret = receive_response(sd_client, third_msg, third_msg_len);
	

	// iv
	unsigned char* iv = (unsigned char*)malloc((12+1) * sizeof(unsigned char));
	memcpy(iv, &third_msg[0], 12);
	iv[12] = '\0';

	// e_session_key
	int e_session_key_len_uc_len = third_msg[12];

	unsigned char* e_session_key_len_uc = (unsigned char*)malloc((e_session_key_len_uc_len+1) * sizeof(unsigned char));
	memcpy(e_session_key_len_uc, &third_msg[12 + 1], e_session_key_len_uc_len);
	e_session_key_len_uc[e_session_key_len_uc_len] = '\0';		
	long int e_session_key_len = atol((const char*)e_session_key_len_uc);

	unsigned char* e_session_key = (unsigned char*)malloc((e_session_key_len+1) * sizeof(unsigned char));
	memcpy(e_session_key, &third_msg[12 + 1 + e_session_key_len_uc_len], e_session_key_len);
	e_session_key[e_session_key_len] = '\0';
	
	// e_symmetric_key
	int e_symmetric_key_len_uc_len = third_msg[12 + 1 + e_session_key_len_uc_len + e_session_key_len];

	unsigned char* e_symmetric_key_len_uc = (unsigned char*)malloc((e_symmetric_key_len_uc_len+1) * sizeof(unsigned char));
	memcpy(e_symmetric_key_len_uc, &third_msg[12 + 2 + e_session_key_len_uc_len + e_session_key_len], e_symmetric_key_len_uc_len);
	e_symmetric_key_len_uc[e_symmetric_key_len_uc_len] = '\0';		
	int e_symmetric_key_len = atoi((const char*)e_symmetric_key_len_uc);

	unsigned char* e_symmetric_key = (unsigned char*)malloc((e_symmetric_key_len+1) * sizeof(unsigned char));
	memcpy(e_symmetric_key, &third_msg[12 + 2 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len], e_symmetric_key_len);
	e_symmetric_key[e_symmetric_key_len] = '\0';
	
	// signature
	int signature_len_uc_len = third_msg[12 + 2 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len + e_symmetric_key_len];
	
	unsigned char* signature_len_uc = (unsigned char*)malloc((signature_len_uc_len+1) * sizeof(unsigned char));
	memcpy(signature_len_uc, &third_msg[12 + 3 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len + e_symmetric_key_len], signature_len_uc_len);
	signature_len_uc[signature_len_uc_len] = '\0';
	
	int signature_len = atoi((const char*)signature_len_uc);
	

	unsigned char* signature = (unsigned char*)malloc((signature_len+1) * sizeof(unsigned char));
	memcpy(signature, &third_msg[12 + 3 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len + e_symmetric_key_len + signature_len_uc_len], signature_len);
	signature[signature_len] = '\0';

	
	// load nonce_server_len
	string aux = to_string(nonce_server);
	int nonce_server_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_server_uc = (unsigned char*)malloc((nonce_server_len + 1) * sizeof(unsigned char));
	memcpy(&nonce_server_uc[0], aux.c_str(), nonce_server_len);
	nonce_server_uc[nonce_server_len] = '\0';
	
	// load nonce_client_len
	nonce_client = nonce_client + 1;
	aux = to_string(nonce_client);
	int nonce_client_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_client_uc = (unsigned char*)malloc((nonce_client_len + 1) * sizeof(unsigned char));
	memcpy(&nonce_client_uc[0], aux.c_str(), nonce_client_len);
	nonce_client_uc[nonce_client_len] = '\0';

	// preparing the plaintext to sign
	int plaintext_len = nonce_server_len + nonce_client_len + e_session_key_len + 12 + e_symmetric_key_len;
	char* plaintext = (char*)malloc((plaintext_len+1) * sizeof(char));
	pulisci((unsigned char*) plaintext);

	memcpy(&plaintext[0], nonce_server_uc, nonce_server_len);
	memcpy(&plaintext[nonce_server_len], nonce_client_uc, nonce_client_len);
	memcpy(&plaintext[nonce_server_len + nonce_client_len], iv, 12);
	memcpy(&plaintext[nonce_server_len + nonce_client_len + 12], e_session_key, e_session_key_len);
	memcpy(&plaintext[nonce_server_len + nonce_client_len + 12 + e_session_key_len], e_symmetric_key, e_symmetric_key_len);
	plaintext[plaintext_len] = '\0';


	// verify the signature
	long int signature_verify = dig_sign_verify(signature, signature_len, public_key, (unsigned char*)plaintext, plaintext_len);

	int symmetric_key_len = 0;
	unsigned char* symmetric_key = (unsigned char*)malloc((16+1) * sizeof(unsigned char));
	if(signature_verify == 1){
		// get the session key
		symmetric_key_len = get_symmetric_key(e_session_key, e_session_key_len, iv, ephemeral_private_key, e_symmetric_key, e_symmetric_key_len, symmetric_key);
		symmetric_key[16] = '\0';
	}
	else 
		exit(1);
		
	return symmetric_key;

}


// *********** CLIENT MESSAGES *************

void send_first_message (int sd, uint32_t nonce_client, EVP_PKEY*& private_key) {

	// The client starts the authentication
	string username, long_term_private_file; 
	
	cout << "Insert username: ";
	getline(cin, username);
	
	if (!cin || username.size() > 20) {
		// Handle error
		cout << "Error occurred: invalid input or too many characters(max 20 characters)" << endl;
		exit(1);
	}
	
	if(!check_input(username)) {
		cout << "Error occurred: wrong username format! You can only use a:z A:Z 1234567890-.\'@" << endl;
		exit(1);
	}
	
	long_term_private_file = "./Client/" + username + "_key.pem";
		
	while(1){
		FILE* private_key_file = fopen((const char*)long_term_private_file.c_str(), "r");
		if(!private_key_file) {
			cout << "User not found!" << endl;
			exit(1);
		}	
		private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
		fclose(private_key_file);
		if(!private_key) cout << "Error during the digit of the password, retry. (In this example of project the passord is \"studenti\")." << endl;
		else break;
	}
	
	// username
	int user_len = strlen((const char*)username.c_str());
	unsigned char* user = (unsigned char*)malloc((user_len + 1) * sizeof(unsigned char));
	memcpy(&user[0], username.c_str(), user_len);
	user[user_len] = '\0';
	
	// load the client cert
	long int client_cert_size;
	unsigned char* client_cert = get_client_cert(client_cert_size, user, user_len);
	client_cert[client_cert_size] = '\0';	
	
	// nonce_client
	string aux = to_string(nonce_client);
	int nonce_client_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_client_uc = (unsigned char*)malloc((nonce_client_len + 1) * sizeof(unsigned char));
	memcpy(&nonce_client_uc[0], aux.c_str(), nonce_client_len);
	nonce_client_uc[nonce_client_len] = '\0';
	
	// client_cer_size
	unsigned char* client_cert_size_uc = (unsigned char*)malloc((to_string(client_cert_size).size()+1) * sizeof(unsigned char));
	client_cert_size_uc = (unsigned char*)to_string(client_cert_size).c_str();
	client_cert_size_uc[to_string(client_cert_size).size()] = '\0';
	int client_cert_size_uc_len = strlen((const char*)client_cert_size_uc);	
	
	// first_msg
	int first_msg_len = 1 + nonce_client_len + 1 + client_cert_size_uc_len + client_cert_size + 1 + user_len;
	char* first_msg = (char*)malloc((first_msg_len + 1) * sizeof(char));
	
	// nonce_client
	memcpy(&first_msg[0], &nonce_client_len, 1);
	memcpy(&first_msg[1], nonce_client_uc, nonce_client_len);
	
	// client_cert
	memcpy(&first_msg[1 + nonce_client_len], &client_cert_size_uc_len, 1);
	memcpy(&first_msg[2 + nonce_client_len], client_cert_size_uc, client_cert_size_uc_len);
	memcpy(&first_msg[2 + nonce_client_len + client_cert_size_uc_len], client_cert, client_cert_size);
	
	// user
	memcpy(&first_msg[2 + nonce_client_len + client_cert_size_uc_len + client_cert_size], &user_len, 1);
	memcpy(&first_msg[3 + nonce_client_len + client_cert_size_uc_len + client_cert_size], user, user_len);
	

	int ret = send_response(sd, (unsigned char*)first_msg, first_msg_len);
	
}

EVP_PKEY* receive_second_message(int sd, uint32_t &nonce_server, uint32_t nonce_client, EVP_PKEY* &public_key) {

	uint16_t second_msg_len;
	char* second_msg;
	int ret = receive_response(sd, second_msg, second_msg_len);
	 
	// nonce_server
	int nonce_server_len = second_msg[0];
	
	unsigned char* nonce_server_uc = (unsigned char*)malloc((nonce_server_len + 1) * sizeof(unsigned char));
	memcpy(nonce_server_uc, &second_msg[1], nonce_server_len);
	nonce_server_uc[nonce_server_len] = '\0';
	
	// cert_server
	int cert_server_size_uc_len = second_msg[1 + nonce_server_len];
	
	unsigned char* cert_server_size_uc = (unsigned char*)malloc((cert_server_size_uc_len + 1) * sizeof(unsigned char));
	memcpy(cert_server_size_uc, &second_msg[2 + nonce_server_len], cert_server_size_uc_len);
	cert_server_size_uc[cert_server_size_uc_len] = '\0';			
	long int cert_server_size = atol((const char*)cert_server_size_uc);

	unsigned char* cert_server_uc = (unsigned char*)malloc((cert_server_size + 1) * sizeof(unsigned char));
	memcpy(cert_server_uc, &second_msg[2 + nonce_server_len + cert_server_size_uc_len], cert_server_size);
	cert_server_uc[cert_server_size] = '\0';
	X509* cert_server = deserialize_cert(cert_server_uc, cert_server_size);
	
	// eph_public_key
	int eph_public_key_len_uc_len = second_msg[2 + nonce_server_len + cert_server_size_uc_len + cert_server_size];
	
	unsigned char* eph_public_key_len_uc = (unsigned char*)malloc((eph_public_key_len_uc_len + 1) * sizeof(unsigned char));
	memcpy(eph_public_key_len_uc, &second_msg[3 + nonce_server_len + cert_server_size_uc_len + cert_server_size], eph_public_key_len_uc_len);	
	eph_public_key_len_uc[eph_public_key_len_uc_len] = '\0';		
	long int eph_public_key_len = atol((const char*)eph_public_key_len_uc);

	unsigned char* eph_public_key_uc = (unsigned char*)malloc((eph_public_key_len + 1) * sizeof(unsigned char));
	memcpy(eph_public_key_uc, &second_msg[3 + nonce_server_len + cert_server_size_uc_len + cert_server_size + eph_public_key_len_uc_len], eph_public_key_len);
	eph_public_key_uc[eph_public_key_len] = '\0';
	
	// get the ephemeral public key
	EVP_PKEY* ephemeral_public_key = deserialize_public_key(eph_public_key_uc, eph_public_key_len);
	
	// signature
	int signature_len_uc_len = second_msg[3 + nonce_server_len + cert_server_size_uc_len + cert_server_size + eph_public_key_len_uc_len + eph_public_key_len];
	
	unsigned char* signature_len_uc = (unsigned char*)malloc((signature_len_uc_len + 1) * sizeof(unsigned char));
	memcpy(signature_len_uc, &second_msg[4 + nonce_server_len + cert_server_size_uc_len + cert_server_size + eph_public_key_len_uc_len + eph_public_key_len], signature_len_uc_len);	
	signature_len_uc[signature_len_uc_len] = '\0';			
	int signature_len = atoi((const char*)signature_len_uc);
	
	unsigned char* signature = (unsigned char*)malloc((signature_len + 1) * sizeof(unsigned char));
	memcpy(signature, &second_msg[4 + nonce_server_len + cert_server_size_uc_len + cert_server_size + eph_public_key_len_uc_len + eph_public_key_len + signature_len_uc_len], signature_len);
	signature[signature_len] = '\0';
	
	// load the nonce_client_len
	string aux = to_string(nonce_client);
	int nonce_client_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_client_uc = (unsigned char*)malloc((nonce_client_len+1) * sizeof(unsigned char));
	memcpy(&nonce_client_uc[0], aux.c_str(), nonce_client_len);
	nonce_client_uc[nonce_client_len] = '\0';
	
	// verifica della signature
	public_key = X509_get_pubkey(cert_server);
	
	int plaintext_len = nonce_client_len + nonce_server_len + eph_public_key_len;
	char* plaintext = (char*)malloc((plaintext_len+1) * sizeof(char));
	memcpy(&plaintext[0], nonce_client_uc, nonce_client_len);
	memcpy(&plaintext[nonce_client_len], nonce_server_uc, nonce_server_len);
	memcpy(&plaintext[nonce_client_len + nonce_server_len], eph_public_key_uc, eph_public_key_len);
	plaintext[plaintext_len] = '\0';

	int signature_verify = dig_sign_verify(signature, signature_len, public_key, (unsigned char*)plaintext, plaintext_len);
	
	if(signature_verify == 1){
		nonce_server = atol((const char*)nonce_server_uc);
	}
	
	X509_STORE* cert_store = NULL;
	init_cert_store_client(cert_store);
	verify_cert_received(cert_store, cert_server);
	
	return ephemeral_public_key;
}


unsigned char* send_third_message(int sd, uint32_t& nonce_client, uint32_t nonce_server, EVP_PKEY* ephemeral_public_key, EVP_PKEY* private_key) {

	unsigned char* e_session_key = NULL;
	unsigned char* iv = NULL;
	int e_session_key_len;
	
	unsigned char* symmetric_key = (unsigned char*)malloc((16 + 1) * sizeof(unsigned char));
	symmetric_key = random_generator(16);
	symmetric_key[16] = '\0';
	
	unsigned char* e_symmetric_key = (unsigned char*)malloc((16 + 16 + 1) * sizeof(unsigned char));
	
	// generate the symmetric key
	int e_symmetric_key_len = generate_crypto_variables(e_session_key, e_session_key_len, iv, ephemeral_public_key, symmetric_key, e_symmetric_key);

	e_symmetric_key[e_symmetric_key_len] = '\0';

	// nonce_server
	string aux = to_string(nonce_server);
	int nonce_server_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_server_uc = (unsigned char*)malloc((nonce_server_len + 1) * sizeof(unsigned char));
	memcpy(&nonce_server_uc[0], aux.c_str(), nonce_server_len);
	nonce_server_uc[nonce_server_len] = '\0';

	// nonce_client
	nonce_client = nonce_client + 1;
	aux = to_string(nonce_client);
	int nonce_client_len = strlen((const char*)aux.c_str());
	unsigned char* nonce_client_uc = (unsigned char*)malloc((nonce_client_len + 1) * sizeof(unsigned char));
	memcpy(&nonce_client_uc[0], aux.c_str(), nonce_client_len);
	nonce_client_uc[nonce_client_len] = '\0';
	
	// preparing the plaintext to sign
	int plaintext_len = nonce_server_len + nonce_client_len + e_session_key_len + 12 + e_symmetric_key_len;
	char* plaintext = (char*)malloc((plaintext_len + 1) * sizeof(char));
	memcpy(&plaintext[0], nonce_server_uc, nonce_server_len);
	memcpy(&plaintext[nonce_server_len], nonce_client_uc, nonce_client_len);
	memcpy(&plaintext[nonce_server_len + nonce_client_len], iv, 12);
	memcpy(&plaintext[nonce_server_len + nonce_client_len + 12], e_session_key, e_session_key_len);
	memcpy(&plaintext[nonce_server_len + nonce_client_len + 12 + e_session_key_len], e_symmetric_key, e_symmetric_key_len);
	plaintext[plaintext_len] = '\0';

	// signature
	int signature_len = EVP_PKEY_size(private_key);
	unsigned char* signature = (unsigned char*)malloc((signature_len + 1) * sizeof(unsigned char));
	
	signature_len = dig_sign_sgn((unsigned char*)plaintext, plaintext_len, private_key, (unsigned char*)signature);
	signature[signature_len] = '\0';
	
	unsigned char* signature_len_uc = (unsigned char*)malloc((to_string(signature_len).size() + 1) * sizeof(unsigned char));
	signature_len_uc = (unsigned char*)to_string(signature_len).c_str();
	signature_len_uc[(to_string(signature_len).size())] = '\0';
	int signature_len_uc_len = strlen((const char*)signature_len_uc);
	
	// e_session_key	
	unsigned char* e_session_key_len_uc = (unsigned char*)malloc((to_string(e_session_key_len).size() + 1) * sizeof(char));
	e_session_key_len_uc = (unsigned char*)to_string(e_session_key_len).c_str();
	e_session_key_len_uc[(to_string(e_session_key_len).size())] = '\0';
	int e_session_key_len_uc_len = strlen((const char*) e_session_key_len_uc);
	
	// e_symmetric_key
	unsigned char* e_symmetric_key_len_uc = (unsigned char*)malloc((to_string(e_symmetric_key_len).size() + 1) * sizeof(char));
	e_symmetric_key_len_uc = (unsigned char*)to_string(e_symmetric_key_len).c_str();
	e_symmetric_key_len_uc[(to_string(e_symmetric_key_len).size())] = '\0';
	int e_symmetric_key_len_uc_len = strlen((const char*) e_symmetric_key_len_uc);
	
	// third_msg
	int third_msg_len = 12 + 1 + e_session_key_len_uc_len + e_session_key_len + 1 + e_symmetric_key_len_uc_len + e_symmetric_key_len + 1 + signature_len_uc_len + signature_len;
	char* third_msg = (char*)malloc((third_msg_len + 1) * sizeof(char));
	

	// iv
	memcpy(&third_msg[0], iv, 12);
	
	// e_session_key
	memcpy(&third_msg[12], &e_session_key_len_uc_len, 1);
	memcpy(&third_msg[12 + 1], e_session_key_len_uc, e_session_key_len_uc_len);
	memcpy(&third_msg[12 + 1 + e_session_key_len_uc_len], e_session_key, e_session_key_len);
	
	// e_symmetric_key
	memcpy(&third_msg[12 + 1 + e_session_key_len_uc_len + e_session_key_len], &e_symmetric_key_len_uc_len, 1);
	memcpy(&third_msg[12 + 2 + e_session_key_len_uc_len + e_session_key_len], e_symmetric_key_len_uc, e_symmetric_key_len_uc_len);
	memcpy(&third_msg[12 + 2 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len], e_symmetric_key, e_symmetric_key_len);

	// signature
	memcpy(&third_msg[12 + 2 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len + e_symmetric_key_len], &signature_len_uc_len, 1);
	memcpy(&third_msg[12 + 3 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len + e_symmetric_key_len], signature_len_uc, signature_len_uc_len);
	memcpy(&third_msg[12 + 3 + e_session_key_len_uc_len + e_session_key_len + e_symmetric_key_len_uc_len + e_symmetric_key_len + signature_len_uc_len], signature, signature_len);
	
	third_msg[third_msg_len] = '\0';

	int ret = send_response(sd, (unsigned char*)third_msg, third_msg_len);

	return symmetric_key;

}


