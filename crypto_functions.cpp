#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using namespace std;

int handleErrors(){
	cout << "An error occurred" << endl;
	exit(1);
}

unsigned char* random_generator(int len) {

	int ret;
	unsigned char* random = (unsigned char*)malloc(len);
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&random[0], len);
	if(ret!=1){
		cerr <<"Error: RAND_bytes Failed\n";
		exit(1);
	}
  
	return random;
}

bool check_input(string input){

	if(input.empty()) return false;
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "1234567890-.\'@"; 
    if(input.find_first_not_of(ok_chars) != string::npos) return false;
    return true;

}


int Encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int len=0;
	int ciphertext_len=0;
	
	// Create and initialise the context
	if(!(ctx = EVP_CIPHER_CTX_new()))
	    handleErrors();
	    
	// Initialise the encryption operation.
	if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
	    handleErrors();
	    
	//Provide any AAD data. This can be called zero or more times as required
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
	    handleErrors();
	   

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	    handleErrors();
	  
	ciphertext_len = len;
	
	//Finalize Encryption
	if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
	    handleErrors();

	ciphertext_len += len;
	
	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
	    handleErrors();
	
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int Decrypt(unsigned char *ciphertext, int ciphertext_len,
			unsigned char *aad, int aad_len,
			unsigned char *tag,
			unsigned char *key,
			unsigned char *iv, int iv_len,
			unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
		
	if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
		handleErrors();
		
	//Provide any AAD data.
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();
	
	//Provide the message to be decrypted, and obtain the plaintext output.
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	 	
	plaintext_len = len;
	
	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
		handleErrors();
	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal(ctx, plaintext + len, &len);
	

	/* Clean up */
	EVP_CIPHER_CTX_cleanup(ctx);
	//cout << "ret: " << ret << endl;

	if(ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	} else {
		/* Verify failed */
		return -1;
	}
}

int send_cipher(int client, unsigned char *msg, uint32_t &counter, unsigned char* symmetric_key, int msg_size = 0) {

	uint16_t size;
	int msg_len = (msg_size)? msg_size : (strlen((const char*)msg)+1);
	unsigned char* iv_gcm = (unsigned char*)malloc((12+1)*sizeof(unsigned char));
	unsigned char *cphr_buf = (unsigned char*)malloc((msg_len+16+1)*sizeof(unsigned char));
	unsigned char *tag_buf = (unsigned char*)malloc((16+1)*sizeof(unsigned char));
	int cphr_len;
	
	iv_gcm = random_generator(12);
	iv_gcm[12] = '\0';
	
	// counter update
	counter = counter + 1;
	string aux = to_string(counter);
	int counter_len = strlen((const char*)aux.c_str());
	unsigned char* counter_uc = (unsigned char*)malloc((counter_len+1) * sizeof(unsigned char));
	memcpy(&counter_uc[0], aux.c_str(), counter_len);
	counter_uc[counter_len] = '\0';
	
	// AAD
	int aad_len = 1 + counter_len + 12;
	unsigned char* aad = (unsigned char*)malloc((aad_len + 1)*sizeof(unsigned char));
	memcpy(&aad[0], &counter_len, 1);
	memcpy(&aad[1], counter_uc, counter_len);
	memcpy(&aad[1 + counter_len], iv_gcm, 12);
	aad[aad_len] = '\0';
	
	
	// Encrypt
	cphr_len = Encrypt(msg, msg_len, aad, aad_len, symmetric_key, iv_gcm, 12, cphr_buf, tag_buf);
	tag_buf[16] = '\0';
	cphr_buf[msg_len+16] = '\0';
	
	unsigned char* cphr_len_uc = (unsigned char*)malloc((to_string(cphr_len).size()+1) * sizeof(unsigned char));
	cphr_len_uc = (unsigned char*)to_string(cphr_len).c_str();
	cphr_len_uc[to_string(cphr_len).size()] = '\0';
	int cphr_len_uc_len = strlen((const char*)cphr_len_uc);
	

	size = htons(1 + aad_len + 16 + 1 + + cphr_len_uc_len + cphr_len);

	int ret = send(client, (void*)&size, sizeof(uint16_t), 0);
	if (ret < 0) {
		perror("Error occurred during the send of the size"); 
		return ret;
	}
	
	uint16_t tot_buf_len = 1 + aad_len + 1 + cphr_len_uc_len + cphr_len + 16;
	unsigned char* tot_buf = (unsigned char*)malloc((tot_buf_len+1)*sizeof(unsigned char));
	
	// inserisce iv, tag e ciphertext nel buffer
	memcpy(&tot_buf[0], &aad_len, 1);
	memcpy(&tot_buf[1], aad, aad_len);
	memcpy(&tot_buf[1 + aad_len], &cphr_len_uc_len, 1);
	memcpy(&tot_buf[2 + aad_len], cphr_len_uc, cphr_len_uc_len);
	memcpy(&tot_buf[2 + aad_len + cphr_len_uc_len], cphr_buf, cphr_len);
	memcpy(&tot_buf[2 + aad_len + cphr_len_uc_len + cphr_len], tag_buf, 16);
	tot_buf[tot_buf_len] = '\0';
	
	
	ret = send(client, (void*)tot_buf, tot_buf_len, 0);
	if (ret < 0)
		perror("Error occurred during the send of the message"); 
	
	return ret;

}


unsigned char* receive_cipher(int client, unsigned char* buffer, uint32_t &counter, unsigned char* symmetric_key, int msg_len = 0) {

	uint16_t lmsg, len;
	int ret;
	unsigned char* iv_gcm = (unsigned char*)malloc((12+1)*sizeof(unsigned char));
	unsigned char *tag_buf = (unsigned char*)malloc((16+1)*sizeof(unsigned char));
	unsigned char* cphr_buf;
	unsigned char *dec_buf;
	int dec_len;
	uint32_t check_value = counter + 1; 
	
	ret = recv(client, (void*)&lmsg, sizeof(uint16_t), 0);
	if(ret < 0) {
		perror("Error occurred during the receive of the size");
		return NULL;
	}
	
	len = msg_len ? msg_len : ntohs(lmsg);
	buffer = (unsigned char*)malloc((len+1) * sizeof(unsigned char));

	ret = recv(client, (void*)buffer, len, 0);
	if (ret < 0) {
		perror("Error occurred during the send of the message");
		return NULL;
	}
	
	buffer[len] = '\0';
	
	// recover clear values and cipher values
	
	// aad
	int aad_len = buffer[0];
	unsigned char* aad = (unsigned char*) malloc((aad_len+1) * sizeof(unsigned char));
	memcpy(aad, &buffer[1], aad_len);
	aad[aad_len] = '\0';
	
	// counter
	int counter_len = aad[0];
	unsigned char* counter_uc = (unsigned char*) malloc((counter_len+1) * sizeof(unsigned char));
	memcpy(counter_uc, &aad[1], counter_len);
	counter_uc[counter_len] = '\0';
	
	// counter check - Has it returned to zero?
	if(atol((const char*)counter_uc) == 0) {
		cout << "The counter need a refresh. Session closed" << endl;
		exit(1);
	}
	
	//iv
	memcpy(iv_gcm, &aad[1 + counter_len], 12);
	iv_gcm[12] = '\0';

		
	// ciphertext
	int cphr_len_uc_len = buffer[1 + aad_len];
	
	unsigned char* cphr_len_uc = (unsigned char*)malloc((cphr_len_uc_len+1) * sizeof(unsigned char));
	memcpy(cphr_len_uc, &buffer[2 + aad_len], cphr_len_uc_len);
	cphr_len_uc[cphr_len_uc_len] = '\0';
	int cphr_len = atoi((const char*)cphr_len_uc);
	
	cphr_buf = (unsigned char*)malloc((cphr_len+1) * sizeof(unsigned char));
	dec_buf = (unsigned char*)malloc((cphr_len+1) * sizeof(unsigned char)); 
	
	memcpy(cphr_buf, &buffer[2 + aad_len + cphr_len_uc_len], cphr_len);
	cphr_buf[cphr_len] = '\0';

	//tag
	memcpy(tag_buf, &buffer[2 + aad_len + cphr_len_uc_len + cphr_len], 16);
		tag_buf[16] = '\0';


	// decripta il ciphertext
	dec_len = Decrypt(cphr_buf, cphr_len, aad, aad_len, tag_buf, symmetric_key, iv_gcm, 12, dec_buf);
	if(dec_len < 0) {
		cout << "Error occurred during the decryption of the message" << endl;
		return NULL;
	}
	dec_buf[cphr_len] = '\0';
	
	// Controllo del contatore
	if(atol((const char*)counter_uc) != check_value) {
		cout << "Replay attack?" << endl;
		return NULL;
	}
	else
		counter = check_value;
	
	return dec_buf;
}


long int dig_sign_sgn(unsigned char* plaintext, int plaintext_len, EVP_PKEY* private_key, unsigned char* signature) {

	unsigned int signature_len;
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	
	EVP_SignInit(ctx, EVP_sha256());
	
	EVP_SignUpdate(ctx, plaintext, plaintext_len);
	
	EVP_SignFinal(ctx, signature, &signature_len, private_key);
	
	EVP_MD_CTX_free(ctx);
	
	return signature_len;

}

int dig_sign_verify(unsigned char* signature, long int signature_len, EVP_PKEY* public_key, unsigned char* plaintext, int plaintext_len) {

	if(!signature) cout << "not signature" << endl;
	if(!public_key) cout << "not public_key" << endl;
	if(!plaintext) cout << "not plaintext" << endl;
	
	int ret;
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(!ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }
	
	EVP_VerifyInit(ctx, EVP_sha256());

	EVP_VerifyUpdate(ctx, plaintext, plaintext_len);
	
	ret = EVP_VerifyFinal(ctx, signature, signature_len, public_key);

	EVP_MD_CTX_free(ctx);
	
	if(ret == 0) {
		cout << "Invalid signature" << endl;
		return 0;
	}
	
	if(ret < 0) {
		cout << "Error" << endl;
		return -1;
	}	
	
	cout << "Signature verified" << endl;
	return 1;
		
}


unsigned char* serialize_public_key(EVP_PKEY* public_key, int& pub_key_size) {

	unsigned char* eph_public_key = NULL;
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, public_key);
	pub_key_size = BIO_get_mem_data(bio, &eph_public_key);
	if(pub_key_size < 0){
		cout << "Error" << endl;
	exit(1);
	}
	return eph_public_key;
}

X509* deserialize_cert(unsigned char* cert_buff, int cert_size){

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, cert_buff, cert_size);

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);
    return cert;

}

EVP_PKEY* deserialize_public_key(unsigned char* key_buff, int key_size) {

	BIO* bio = BIO_new(BIO_s_mem());
	BIO_write(bio, key_buff, key_size);
	
	EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	
	BIO_free(bio);
	return public_key;

}


unsigned char* get_cert(long int &size) {
	string cert_file_name = "./Server/server_cert.pem";
	// get the file size: 
	// (assuming no failures in fseek() and ftell())
	
	FILE* cert_file = fopen(cert_file_name.c_str(), "r");
	if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }
	X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	
	fclose(cert_file);
	if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
	
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert); // Write server_cert into bio

	// Serialize the certificate
	unsigned char* buff_cert = NULL;
	size = BIO_get_mem_data(bio, &buff_cert);
	if((size) < 0){
		return NULL;
	}

	return buff_cert;
}

unsigned char* get_client_cert(long int &size, unsigned char* user, int user_len) {
	
	string username(reinterpret_cast<char const*>(user), user_len);
	string cert_file_name = "./Client/" + username + "_cert.pem";
	
	FILE* cert_file = fopen(cert_file_name.c_str(), "r");
	if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }
	X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	
	fclose(cert_file);
	if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
	
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert); // Write server_cert into bio

	// Serialize the certificate
	unsigned char* buff_cert = NULL;
	size = BIO_get_mem_data(bio, &buff_cert);
	if((size) < 0){
		return NULL;
	}

	return buff_cert;
}


void init_cert_store_server (X509_STORE* &cert_store) {
	
	int ret;
	// load the CA's certificate:
	string cacert_file_name = "./Server/CA_Applied_cert.pem";
	FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
	if(!cacert_file) { cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
	X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
	fclose(cacert_file);
	if(!cacert) { cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
	
	cert_store = X509_STORE_new();
	ret = X509_STORE_add_cert(cert_store, cacert);
	if(ret != 1) {
		cout << "Error occurred during X509_STORE_add_cert" << endl;
		exit(1);
	}
	
	string crl_filename = "./Server/CA_Applied_crl.pem";
	FILE* crl_file = fopen(crl_filename.c_str(), "r");
	if(!crl_file){ cerr << "Error: cannot open file '" << crl_filename << "' (missing?)\n"; exit(1); }
	X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
	
	fclose(crl_file);
	if(!crl){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
	
	ret = X509_STORE_add_crl(cert_store, crl);
	
}

void init_cert_store_client (X509_STORE* &cert_store) {
	
	int ret;
	// load the CA's certificate:
	string cacert_file_name = "./Client/CA_Applied_cert.pem";
	FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
	if(!cacert_file) { cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
	X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
	fclose(cacert_file);
	if(!cacert) { cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
	
	cert_store = X509_STORE_new();
	ret = X509_STORE_add_cert(cert_store, cacert);
	if(ret != 1) {
		cout << "Error occurred during X509_STORE_add_cert" << endl;
		exit(1);
	}
	
	string crl_filename = "./Client/CA_Applied_crl.pem";
	FILE* crl_file = fopen(crl_filename.c_str(), "r");
	if(!crl_file){ cerr << "Error: cannot open file '" << crl_filename << "' (missing?)\n"; exit(1); }
	X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
	
	fclose(crl_file);
	if(!crl){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
	
	ret = X509_STORE_add_crl(cert_store, crl);
	
}

void verify_cert_received (X509_STORE* cert_store, X509* cert) {
	
	int ret;
	X509_STORE_CTX* cert_store_ctx = X509_STORE_CTX_new();
	ret = X509_STORE_CTX_init(cert_store_ctx, cert_store, cert, NULL);
	if(ret != 1) {
		cerr << "Error occurred during X509_STORE_CTX_init" << endl;
		exit(1);
	}

	ret = X509_verify_cert(cert_store_ctx);
	if(ret < 0) {
		cerr << "Error occurred during X509_verify_cert" << endl;
		exit(1);
	}
	
	if(ret == 0) {
		cerr << "The certificate cannot be verified" << endl;
		exit(1);
	}
	
	// print the successful verification to screen:
	char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
	free(tmp);
	free(tmp2);
	X509_STORE_CTX_free(cert_store_ctx);

}


void generate_ephemeral_keys(EVP_PKEY** prv, EVP_PKEY** pub) {

    RSA *rsa = NULL;
    BIGNUM* big_num = NULL;
    BIO *bio = NULL;
    BIO *bio_pub = NULL;


    // Generate RSA key
    big_num = BN_new();
    BN_set_word(big_num, RSA_F4);
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, big_num, NULL);
    BN_free(big_num);


    // Extract the private key from rsa struct
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_read_bio_PrivateKey(bio, &(*prv), NULL, NULL);
    BIO_free_all(bio);


    // Extract the public key from the private key
    bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, *prv);
    PEM_read_bio_PUBKEY(bio_pub, &(*pub), NULL, NULL);
    BIO_free_all(bio_pub);

}

int generate_crypto_variables(unsigned char* &encrypted_key, int &encrypted_key_len, unsigned char* &iv, EVP_PKEY* ephemeral_public_key, unsigned char* symmetric_key, unsigned char* &e_symmetric_key) {

	// declare some useful variables:
	const EVP_CIPHER* cipher = EVP_aes_128_gcm();
	encrypted_key_len = EVP_PKEY_size(ephemeral_public_key);
	int iv_len = EVP_CIPHER_iv_length(cipher);
	int block_size = EVP_CIPHER_block_size(cipher);

	// create the envelope context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }

	// allocate buffers for encrypted key and IV:
	encrypted_key = (unsigned char*)malloc(encrypted_key_len * sizeof(unsigned char));
	iv = (unsigned char*)malloc(iv_len * sizeof(unsigned char));
	if(!encrypted_key || !iv) { cerr << "Error: malloc returned NULL (encrypted key too big?)\n"; exit(1); }

	// encrypt the plaintext:
	int ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &ephemeral_public_key, 1);
	if(ret <= 0){ // it is "<=0" to catch the (undocumented) case of -1 return value, when the operation is not supported (e.g. attempt to use digital envelope with Elliptic Curve keys)
		cerr <<"Error: EVP_SealInit returned " << ret <<"\n";
		exit(1);
	}
	
	e_symmetric_key = (unsigned char*)malloc(32 * sizeof(unsigned char));
	
	int outlen = 0;
	int e_symmetric_key_len = 0;
	if(1 != EVP_SealUpdate(ctx, e_symmetric_key, &outlen, symmetric_key, 16))
		handleErrors();
		
	e_symmetric_key_len = outlen;
	
	
	EVP_CIPHER_CTX_free(ctx);
	return e_symmetric_key_len;
	
}	


int get_symmetric_key(unsigned char* encrypted_key, int encrypted_key_len, unsigned char* iv, EVP_PKEY* ephemeral_private_key, unsigned char* e_symmetric_key, int e_symmetric_key_len, unsigned char* symmetric_key) {

	const EVP_CIPHER* cipher = EVP_aes_128_gcm();
	int iv_len = EVP_CIPHER_iv_length(cipher);
	int block_size = EVP_CIPHER_block_size(cipher);
	int len;

	// create the envelope context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(!ctx){ 
		cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; 
		exit(1); 
	}
	
	
	int session_key_len = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, ephemeral_private_key);
	
	
	if(!EVP_OpenUpdate(ctx, symmetric_key, &len, e_symmetric_key, e_symmetric_key_len))
		handleErrors();
	
	int symmetric_key_len = len;
	
	EVP_CIPHER_CTX_cleanup(ctx);

	
	return symmetric_key_len;
}

	
	
	
	
	
	
	
	
	
	
	
