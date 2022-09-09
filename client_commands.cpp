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
#include "crypto_functions.cpp"
using namespace std;


void pulisci(unsigned char* buffer) {  /* pulisce il buffer */

	int i, dim = strlen((const char*)buffer)+1;
	for(i = 0; i < dim; i++)
		buffer[i] = '\0';
}


int send_response(int client, unsigned char *msg, int len) {  // invia dim e msg
   
	uint16_t size = htons(len);

	int ret = send(client, (void*)&size, sizeof(uint16_t), 0);
	if (ret < 0)
		perror("Error occurred during the send of the size"); 

	ret = send(client, (void*)msg, len, 0);
	if (ret < 0)
		perror("Error occurred during the send of the message"); 

	return ret;

}


int receive_response(int client, char* &buffer, uint16_t &len) {  // riceve dim e msg 

	uint16_t lmsg;
	int ret;

	ret = recv(client, (void*)&lmsg, sizeof(uint16_t), 0);
	if(ret < 0)
		perror("Error occurred during the receive of the size");

	len = ntohs(lmsg);
	
	buffer = (char*)malloc((len+1)*sizeof(char));
	
	ret = recv(client, (void*)buffer, len, 0);
	if(ret < 0)
		perror("Error occurred during the receive of the message");
	
	buffer[len] = '\0';
	
	return ret;    
}



int log_out(int sd_server, uint32_t &counter, unsigned char* symmetric_key) {  

	unsigned char* buf = NULL;
	unsigned char* msg = NULL;

	msg = receive_cipher(sd_server, buf, counter, symmetric_key);
	if(!msg)
		return -1;
		
	msg[strlen((const char*)msg)] = '\0';
	
	if(strcmp((const char*)msg, "CLIENT DISCONNECTED") == 0){
		cout << (const char*)msg << endl;
		close(sd_server);
		return 0;
	}
	else 
		return -1;
	
}

void list(int sd_server, uint32_t &counter_server, unsigned char* symmetric_key) {

	unsigned char* buf = NULL;
	unsigned char* msg = NULL;

	msg = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!msg) {
		cout << "Error occured: receive failed" << endl;
		return;
	}
	
	int len = strlen((const char*)msg);
	msg[len] = '\0';
	cout << "files list: " << msg << endl;
	
}

int Rename(int sd_server, uint32_t& counter_client, uint32_t&counter_server, unsigned char* symmetric_key, bool upload = false) {

	unsigned char* buf = NULL;
	string filename;
	if(!upload) {
		cout << "Insert the filename to rename: ";
		getline(cin, filename);
		if(!cin) {
			cout << "Error occurred: invalid input" << endl;
			string confirm = "<error>";
			int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return 0;
			}
			return 0;
		}
		
		int ret = send_cipher(sd_server, (unsigned char*)filename.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return 0;
		}
		
		unsigned char* format = NULL;
		format = receive_cipher(sd_server, buf, counter_server, symmetric_key);
		if(!format) {
			cout << "Error occurred: receive failed" << endl;
			return 0;
		}
		format[strlen((const char*)format)] = '\0';
		
		if(strcmp((const char*)format, "<error_size>") == 0) {
			cout << "Error occurred: too many characters (max 100)" << endl;
			return 0;
		}
		
		if(strcmp((const char*)format, "<error_format>") == 0) {
			cout << "Error occurred: wrong filename format! You can only use a:z A:Z 1234567890-.\'@" << endl;
			return 0;
		}
	
	}
	
	string new_filename;
	cout << "Insert the new filename: ";
	getline(cin, new_filename);
	if(!cin) {
		cout << "Error occurred: invalid input" << endl;
		string confirm = "<error>";
		int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return 0;
		}
		return 0;
	}
	
	int ret = send_cipher(sd_server, (unsigned char*)new_filename.c_str(), counter_client, symmetric_key);
	if(ret < 0) {
		cout << "Error occurred: send failed" << endl;
		return 0;
	}
	
	unsigned char* format_new_fn = NULL;
	format_new_fn = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!format_new_fn) {
		cout << "Error occurred: receive failed" << endl;
		return 0;
	}
	format_new_fn[strlen((const char*)format_new_fn)] = '\0';
	
	if(strcmp((const char*)format_new_fn, "<error_size>") == 0) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		return 0;
	}
	
	if(strcmp((const char*)format_new_fn, "<error_format>") == 0) {
		cout << "Error occurred: wrong filename format! You can only use a:z A:Z 1234567890-.\'@" << endl;
		return 0;
	}
	
	unsigned char* buffer_uc = NULL;
	buffer_uc = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!buffer_uc) {
		cout << "Error occured: receive failed" << endl;
		return 0;
	}
	
	string buffer(reinterpret_cast<char const*>(buffer_uc), strlen((const char*)buffer_uc));
	buffer[buffer.size()] = '\0';
	
	if(!upload) {
		if(buffer == "<error1>") {
			cout << filename << " not found" << endl;
			return 0;
		}
	}
	
	if(buffer == "<error2>") {
		cout << new_filename << " already exists" << endl;
		return 0;
	}
	
	if(buffer == "<error3>") {
		cout << "Error occurred: rename failed" << endl;
		return 0;
	}
	
	if(buffer == "success") {
		cout << "The file has been renamed" << endl;
	}
	
	return 1;

}

void upload(int sd_server, uint32_t &counter_client, uint32_t &counter_server, unsigned char* symmetric_key) {
	
	cout << "Insert the filename: ";
	string filename;
	getline(cin, filename);
	if(!cin) {
		string confirm = "<error>";
		int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		cout << "Error occurred: invalid input" << endl;
		return;
	}
	
	int ret = send_cipher(sd_server, (unsigned char*)filename.c_str(), counter_client, symmetric_key);
	if(ret < 0) {
		cout << "Error occurred: send failed" << endl;
		return;
	}
	
	unsigned char* buf = NULL;
	
	unsigned char* format = NULL;
	format = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!format) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	format[strlen((const char*)format)] = '\0';
	
	if(strcmp((const char*)format, "<error_size>") == 0) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		return;
	}
	
	if(strcmp((const char*)format, "<error_format>") == 0) {
		cout << "Error occurred: wrong filename format! You can only use a:z A:Z 1234567890-.\'@" << endl;
		return;
	}
	
	FILE* fd = fopen((const char*)filename.c_str(), "rb");
	if(!fd) {
		cout << filename << " not found" << endl;
		string confirm = "<error>";
		int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string confirm = "<ok>";
		int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			fclose(fd);
			cout << "Error occurred: send failed" << endl;
			return;
		}
	}
	
	unsigned char* response = NULL;
	response = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!response) {
		fclose(fd);
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	response[strlen((const char*)response)] = '\0';
	
	// possibility to rename the old file
	if(strcmp((const char*)response, "found") == 0) {
		cout << filename << " already exists" << endl;
		cout << "Do you want to rename the old file? y or n (Do not use upper case!): " << endl;
		string rename_confirm;
		getline(cin, rename_confirm);
		if(!cin) {
			string confirm = "<error>";
			int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
			if(ret < 0) {
				fclose(fd);
				cout << "Error occurred: send failed" << endl;
				return;
			}
			fclose(fd);
			cout << "Error occurred: invalid input" << endl;
			return;
		}
		int ret = send_cipher(sd_server, (unsigned char*)rename_confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			fclose(fd);
			cout << "Error occurred: send failed" << endl;
			return;
		}
		
		unsigned char* r_format = NULL;
		r_format = receive_cipher(sd_server, buf, counter_server, symmetric_key);
		if(!r_format) {
			fclose(fd);
			cout << "Error occurred: receive failed" << endl;
			return;
		}
		r_format[strlen((const char*)r_format)] = '\0';
	
		if(strcmp((const char*)r_format, "<error_size>") == 0) {
			fclose(fd);
			cout << "Error occurred: too many characters (max 1)" << endl;
			return;
		}
	
		if(strcmp((const char*)r_format, "<error_format>") == 0) {
			fclose(fd);
			cout << "Error occurred: wrong confirm format! You can only use a:z A:Z 1234567890-.\'@" << endl;
			return;
		}
		
		if(rename_confirm != "y") {
			if(rename_confirm == "n")
				cout << "The old file has not been renamed. Upload failed" << endl;
			else
				cout << "Error occurred: invalid input" << endl;
			fclose(fd);
			return;
		}
			
		ret = Rename(sd_server, counter_client, counter_server, symmetric_key, true);
		if(!ret) {
			fclose(fd);
			return;
		}
	}
	
	fseek(fd, 0, SEEK_END);
	int size = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	
	string size_s = to_string(size);
	ret = send_cipher(sd_server, (unsigned char*)size_s.c_str(), counter_client, symmetric_key);
	if(ret < 0) {
		fclose(fd);
		cout << "Error occurred: send failed" << endl;
		return;
	}
	
	unsigned char* ack_size = NULL;
	ack_size = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!ack_size) {
		fclose(fd);
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	ack_size[strlen((const char*)ack_size)] = '\0';
	
	// possibility to rename the old file
	if(strcmp((const char*)ack_size, "<error_file_size>") == 0) {
		cout << "Impossible to upload files greater than 4GB" << endl;
		fclose(fd);
		return;
	}
	
	if(strcmp((const char*)ack_size, "ok") == 0) {
		cout << "Uploading the file " << filename << "..." << endl;
	}
	
	int res = 0;
	
	while(1) {
		char buffer[32769];
		if(size < 32768)
			res = fread(buffer, 1, size, fd);
		else
			res = fread(buffer, 1, 32768, fd);
		if(res < 0) {
			if(!buffer) 
				cout<< "Error during the reading of the file" << endl;
			break;
		}
		if(size < 32768) {
			buffer[size] = '\0';
			ret = send_cipher(sd_server, (unsigned char*)buffer, counter_client, symmetric_key, size);
			if(ret < 0) {
				fclose(fd);
				cout << "Error occurred: send failed" << endl;
				return;
			}
		}
		else {
			buffer[32768] = '\0';
			ret = send_cipher(sd_server, (unsigned char*)buffer, counter_client, symmetric_key, 32768);
			if(ret < 0) {
				fclose(fd);
				cout << "Error occurred: send failed" << endl;
				return;
			}
		}
		buf = receive_cipher(sd_server, buf, counter_server, symmetric_key);
		if(!buf) {
			fclose(fd);
			cout << "Error occurred: receive failed" << endl;
			return;
		}
		if(strcmp("<error>", (const char*) buf) == 0) {
			counter_client = counter_client - 1;
			res = fread(buffer, 1, -32768, fd);
			continue;
		}
		size -= 32768;
		if(size <= 0) {
			cout << "File Uploaded" << endl;
			break;
		}
		
	}
	fclose(fd);

}


void download(int sd_server, uint32_t &counter_server, uint32_t& counter_client, unsigned char* symmetric_key) {
	
	cout << "Insert the filename: ";
	string filename;
	getline(cin, filename);
	if(!cin) {
		string confirm = "<error>";
		int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		cout << "Error occurred: invalid input" << endl;
		return;
	}
	
	int ret = send_cipher(sd_server, (unsigned char*)filename.c_str(), counter_client, symmetric_key);
	if(ret < 0) {
		cout << "Error occurred: send failed" << endl;
		return;
	}
	
	unsigned char* buf = NULL;
	
	unsigned char* format = NULL;
	format = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!format) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	format[strlen((const char*)format)] = '\0';
	
	if(strcmp((const char*)format, "<error_size>") == 0) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		return;
	}
	
	if(strcmp((const char*)format, "<error_format>") == 0) {
		cout << "Error occurred: wrong filename format! You can only use a:z A:Z 1234567890-.\'@" << endl;
		return;
	}
	
	unsigned char* buffer_filename = NULL;
	buffer_filename = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!buffer_filename) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	buffer_filename[strlen((const char*)buffer_filename)] = '\0';
	
	if(strcmp((const char*)buffer_filename, "<error>") == 0) {
		cout << filename << " not found" << endl;
		return;
	}
	
	FILE* fd = fopen((const char*)filename.c_str(), "wb");
	if(!fd) {
		cout << "Error: file not created" << endl;
		string confirm = "<error>";
		ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string confirm = "<ok>";
		ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			fclose(fd);
			cout << "Error occurred: send failed" << endl;
			return;
		}
	}
	
	if(strcmp((const char*)buffer_filename, "<ok>") == 0) {
		cout << "Downloading the file " << filename << "..." << endl;
	}
	
	unsigned char* buffer_size = NULL;
	buffer_size = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!buffer_size) {
		fclose(fd);
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	buffer_size[strlen((const char*)buffer_size)] = '\0';
	
	int size = atoi((const char*)buffer_size);
	
	string counter_s = to_string(counter_server);
	int counter_len = counter_s.size();
	uint16_t tot_buf_len = 1 + 1 + counter_len + 12 + 12 + 16 + 1;
		
	uint16_t tot_buf_len_32768 = tot_buf_len + 5 + 32768;
	
	
	ret = 0;
	while(1) {
		
		unsigned char* buffer = NULL;
		
		if(size < 32768) {
			string size_s = to_string(size);
			int size_len = size_s.size();
			uint16_t tot_buf_len_size = tot_buf_len + size_len + size;
			buffer = receive_cipher(sd_server, buf, counter_server, symmetric_key, tot_buf_len_size);
			if(!buffer) {
				string error = "<error>";
				counter_server = counter_server + 1;
				ret = send_cipher(sd_server, (unsigned char*)error.c_str(), counter_client, symmetric_key);
				if(ret < 0) {
					fclose(fd);
					cout << "Error occurred: send failed" << endl;
					return;
				}
				continue;
			}
			buffer[size] = '\0';
			ret = fwrite(buffer, 1, size, fd);
		}
		else {
			buffer = receive_cipher(sd_server, buf, counter_server, symmetric_key, tot_buf_len_32768);
			if(!buffer) {
				string error = "<error>";
				ret = send_cipher(sd_server, (unsigned char*)error.c_str(), counter_client, symmetric_key);
				if(ret < 0) {
					fclose(fd);
					cout << "Error occurred: send failed" << endl;
					return;
				}
				continue;
			}
			
			buffer[32768] = '\0';
			ret = fwrite(buffer, 1, 32768, fd);
		}
		string confirm = "<ok>";
		ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
			
		if(ret < 0) {
			fclose(fd); 
			cout<< "Error during the writing of the file" << endl;
			break;
		}
		
		size -= 32768;
		if(0 >= size) {
			fclose(fd);
			cout << "File Downloaded" << endl;
			break;
		}
	}
	return;

}

void Delete(int sd_server, uint32_t& counter_client, uint32_t&counter_server, unsigned char* symmetric_key) {

	string filename;
	cout << "Insert the filename to remove: ";
	getline(cin, filename);
	if(!cin) {
		cout << "Error occurred: invalid input" << endl;
		string confirm = "<error>";
		int ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	
	int ret = send_cipher(sd_server, (unsigned char*)filename.c_str(), counter_client, symmetric_key);
	if(ret < 0) {
		cout << "Error occurred: send failed" << endl;
		return;
	}
	
	unsigned char* buf = NULL;
	
	unsigned char* format = NULL;
	format = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!format) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	format[strlen((const char*)format)] = '\0';
	
	if(strcmp((const char*)format, "<error_size>") == 0) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		return;
	}
	
	if(strcmp((const char*)format, "<error_format>") == 0) {
		cout << "Error occurred: wrong filename format! You can only use a:z A:Z 1234567890-.\'@" << endl;
		return;
	}
	
	unsigned char* buffer_uc = NULL;
	buffer_uc = receive_cipher(sd_server, buf, counter_server, symmetric_key);
	if(!buffer_uc) {
		cout << "Error occured: receive failed" << endl;
		return;
	}
	
	string buffer(reinterpret_cast<char const*>(buffer_uc), strlen((const char*)buffer_uc));
	buffer[buffer.size()] = '\0';
	
	if(buffer == "error1") {
		cout << filename << " not found" << endl;
		return;
	}
	
	if(buffer == "found") {
		// give confirmation
		cout << "Are you sure do you want to remove your file?  y or n(Do not use upper case!): ";
		string confirm;
		getline(cin, confirm);
		if(!cin) {
			cout << "Error occurred: invalid input" << endl;
			confirm = "error2";
			ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return;
			}
			return;
		}
		ret = send_cipher(sd_server, (unsigned char*)confirm.c_str(), counter_client, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		
		unsigned char* delete_confirm = NULL;
		delete_confirm = receive_cipher(sd_server, buf, counter_server, symmetric_key);
		if(!delete_confirm) {
			cout << "Error occured: receive failed" << endl;
			return;
		}
	
		delete_confirm[strlen((const char*)delete_confirm)] = '\0';
	
		if(strcmp((const char*)delete_confirm, "<error_size>") == 0) {
			cout << "Error occurred: too many characters (max 1)" << endl;
			return;
		}
	
		if(strcmp((const char*)delete_confirm, "<error_format>") == 0) {
			cout << "Error occurred: wrong confirm format! You can only use a:z A:Z 1234567890-.\'@" << endl;
			return;
		}	
		
		if(confirm == "y")
			cout << "The file has been removed" << endl;
		else {
			if(confirm == "n")
				cout << "The file has not been removed" << endl;
			else
				cout << "Error occurred: invalid input" << endl;
		}
	}
	
}















