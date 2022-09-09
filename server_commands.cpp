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
#include <dirent.h>
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

void log_out(int client, uint32_t &counter_server, unsigned char* symmetric_key) {

	int ret;
	unsigned char msg[] = "CLIENT DISCONNECTED";
	int msg_len = sizeof(msg);
	unsigned char* buf = (unsigned char*)malloc((msg_len+1) * sizeof(unsigned char));
	memcpy(&buf[0], msg, msg_len);
	buf[msg_len] = '\0';
	
	ret = send_cipher(client, buf, counter_server, symmetric_key);
	if(ret > 0) {
		close(client);
		printf("Client disconnected successfully\n");
		exit(0);
	}
	else
		printf("Error occurred: the client has not been disconnected\n");

}


void list(int sd_client, uint32_t &counter_server, unsigned char* symmetric_key, unsigned char* user, int user_len) {

	string storage;
	string username(reinterpret_cast<char const*>(user), user_len);
	storage = "./Server/" + username;
	
	struct dirent *entry;
	DIR *dir = opendir(storage.c_str());
 
	if (dir == NULL) {
		cout << "folder not found!" << endl;
  	return;
	}
	
	string buffer;
	int dim_aux;
	int i = 0;
	while((entry = readdir(dir)) != NULL) {
		if(strcmp(entry->d_name,  ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;
			
		string aux(reinterpret_cast<char const*>(entry->d_name), strlen(entry->d_name));
		dim_aux = aux.size();
		buffer += aux;
		buffer += " ";
		i = i + dim_aux;
	}
	int len = buffer.size();
	closedir(dir);
	
	int ret = send_cipher(sd_client, (unsigned char*)buffer.c_str(), counter_server, symmetric_key);
	if(ret < 0) {
		cout << "Error occured: send failed" << endl;
		return;
	}
	

}

int Rename(int sd_client, uint32_t& counter_client, uint32_t&counter_server, unsigned char* symmetric_key, unsigned char* user_uc, int user_len, unsigned char* filename_update = NULL) {

	string user(reinterpret_cast<char const*>(user_uc), user_len);
	unsigned char* buf = NULL;
	string filename;
	if(filename_update) {
		string filename_aux(reinterpret_cast<char const*>(filename_update), strlen((const char*)filename_update));
		filename = filename_aux;
	}
	else {
	
		unsigned char* filename_buf = NULL;
		
		filename_buf = receive_cipher(sd_client, buf, counter_client, symmetric_key);
		if(!filename_buf) {
			cout << "Error occured: receive failed" << endl;
			return 0;
		}
		
		string filename_aux(reinterpret_cast<char const*>(filename_buf), strlen((const char*)filename_buf));
		filename_aux[filename_aux.size()] = '\0';
		if(filename_aux == "<error>") {
			cout << "Error occurred on client side" << endl;
			return 0;
		}
		
		if(filename_aux.size() > 100) {
			cout << "Error occurred: too many characters (max 100)" << endl;
			string error = "<error_size>";
			int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return 0;
			}
			return 0;
		}
		
		if(!check_input(filename_aux)) {
			cout << "Error occurred: wrong filename format" << endl;
			string error = "<error_format>";
			int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return 0;
			}
			return 0;
		}
		else {
			string confirm = "<ok>";
			int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return 0;
			}
		}
		filename = filename_aux;
	}	
	
	
	unsigned char* new_filename_buf = NULL;
	new_filename_buf = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!new_filename_buf) {
		cout << "Error occured: receive failed" << endl;
		return 0;
	}
		
	string new_filename(reinterpret_cast<char const*>(new_filename_buf), strlen((const char*)new_filename_buf));
	new_filename[new_filename.size()] = '\0';
	if(new_filename == "<error>") {
		cout << "Error occurred on client side" << endl;
		return 0;
	}
	
	if(new_filename.size() > 100) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		string error = "<error_size>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return 0;
		}
		return 0;
	}
	
	if(!check_input(new_filename)) {
		cout << "Error occurred: wrong filename format" << endl;
		string error = "<error_format>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return 0;
		}
		return 0;
	}
	else {
		string confirm = "<ok>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return 0;
		}
	}

	string to_read = "./Server/" + user + "/" + filename;
	
	// search for the file
	FILE* fd = fopen((const char*)to_read.c_str(), "rb");
	if(!fd) {
		string confirm = "<error1>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return 0;
		}
		cout << filename << " not found" << endl;
		return 0;
	}
	else
		fclose(fd);
	
	string to_change = "./Server/" + user + "/" + new_filename;
	
	FILE* found = fopen((const char*)to_change.c_str(), "rb");
	if(found) {
		string confirm = "<error2>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			fclose(found);
			cout << "Error occurred: send failed" << endl;
			return 0;
		} 
		cout << filename << " already exists" << endl;
		fclose(found);
		return 0;
	}
		
	int ret = rename((const char*)to_read.c_str(), (const char*)to_change.c_str());
  
	if(ret == 0) {
	  	cout << "The file has been renamed" << endl;
	  	string confirm = "success";
	  	int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
	  	if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return 0;
		}
		return 1;
	} 
	else{
		cout << "The file has not been renamed" << endl;
		string confirm = "<error3>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return 0;
		}
		return 0;
	}
		
}		

void upload(int sd_client, uint32_t &counter_client, uint32_t &counter_server, unsigned char* symmetric_key, unsigned char* user_uc, int user_len) {

	string user(reinterpret_cast<char const*>(user_uc), user_len);
	unsigned char* buf = NULL;
	unsigned char* buffer_filename = NULL;
	buffer_filename = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!buffer_filename) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	buffer_filename[strlen((const char*)buffer_filename)] = '\0';
	
	if(strcmp((const char*)buffer_filename, "<error>") == 0) {
		cout << "Error occurred on client side" << endl;
		return;
	}
	
	string filename(reinterpret_cast<char const*>(buffer_filename), strlen((const char*)buffer_filename));
	
	if(filename.size() > 100) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		string error = "<error_size>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	
	if(!check_input(filename)) {
		cout << "Error occurred: wrong filename format" << endl;
		string error = "<error_format>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string confirm = "<ok>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
	}
	
	unsigned char* filename_exist = NULL;
	filename_exist = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!filename_exist) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	filename_exist[strlen((const char*)filename_exist)] = '\0';
	
	if(strcmp((const char*)filename_exist, "<error>") == 0) {
		cout << "Error occurred on client side" << endl;
		return;
	}

	string to_write = "./Server/" + user + "/" + filename;

	FILE* found = fopen((const char*)to_write.c_str(), "rb");
	if(found) {
		string response = "found";
		int ret = send_cipher(sd_client, (unsigned char*)response.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return;
		}
		cout << filename << " already exists" << endl;
		fclose(found);
		
		unsigned char* rename_confirm = NULL;
		rename_confirm = receive_cipher(sd_client, buf, counter_client, symmetric_key);
		if(!rename_confirm) {
			cout << "Error occurred: receive failed" << endl;
			return;
		}
		
		rename_confirm[strlen((const char*)rename_confirm)] = '\0';
		string r_confirm(reinterpret_cast<char const*>(rename_confirm), strlen((const char*)rename_confirm));
		
		if(r_confirm == "<error>") {
			cout << "Error occurred on client side" << endl;
			return;
		}
		
		if(r_confirm.size() > 1) {
			cout << "Error occurred: too many characters (max 1)" << endl;
			string error = "<error_size>";
			int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return;
			}
			return;
		}
	
		if(!check_input(r_confirm)) {
			cout << "Error occurred: wrong confirm format" << endl;
			string error = "<error_format>";
			int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return;
			}
			return;
		}
		else {
			string confirm = "<ok>";
			int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
			if(ret < 0) {
				cout << "Error occurred: send failed" << endl;
				return;
			}
		}
		if(r_confirm != "y") {
			if(r_confirm == "n")
				cout << "The old file has not been renamed. Upload failed" << endl;
			else
				cout << "Error occurred: invalid input" << endl;
			return;
		}
		
		ret = Rename(sd_client, counter_client, counter_server, symmetric_key, user_uc, user_len, (unsigned char*)filename.c_str());
		if(!ret)
			return;
	}
	else {
		string response = "ok";
		int ret = send_cipher(sd_client, (unsigned char*)response.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return;
		}
	}
	
	unsigned char* buffer_size = NULL;
	buffer_size = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!buffer_size) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	buffer_size[strlen((const char*)buffer_size)] = '\0';
	
	if(strcmp((const char*)buffer_size, "<error>") == 0) {
		cout << "Error occurred on client side" << endl;
		return;
	}
	
	int size = atoi((const char*)buffer_size);
	
	if(size >  4294967296) {
		cout << "Impossible to upload files greater than 4GB" << endl;
		string confirm = "<error_file_size>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string response = "ok";
		int ret = send_cipher(sd_client, (unsigned char*)response.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return;
		}
	}

	FILE* fd = fopen((const char*)to_write.c_str(), "wb");
	if(!fd) {
		cout << "Error: file not created" << endl;
		return;
	}
	
	string counter_s = to_string(counter_client);
	int counter_len = counter_s.size();
	uint16_t tot_buf_len = 1 + 1 + counter_len + 12 + 12 + 16 + 1;
		
	uint16_t tot_buf_len_32768 = tot_buf_len + 5 + 32768;
	
	
	int ret = 0;
	while(1) {
		
		unsigned char* buffer = NULL;
		
		if(size < 32768) {
			string size_s = to_string(size);
			int size_len = size_s.size();
			uint16_t tot_buf_len_size = tot_buf_len + size_len + size;
			buffer = receive_cipher(sd_client, buf, counter_client, symmetric_key, tot_buf_len_size);
			if(!buffer) {
				fclose(fd);
				cout << "Error occurred: receive failed" << endl;
				return;
			}
			buffer[size] = '\0';
			ret = fwrite(buffer, 1, size, fd);
		}
		else {
			buffer = receive_cipher(sd_client, buf, counter_client, symmetric_key, tot_buf_len_32768);
			if(!buffer) {
				string error = "<error>";
				ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
				if(ret < 0) {
					fclose(fd);
					cout << "Error occured: send failed" << endl;
					return;
				}
				continue;
			}
			
			buffer[32768] = '\0';
			ret = fwrite(buffer, 1, 32768, fd);
		}
		string confirm = "<ok>";
		ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			fclose(fd); 
			cout<< "Error during the writing of the file" << endl;
			break;
		}
		
		size -= 32768;
		if(0 >= size) {
			fclose(fd);
			break;
		}
	}
	
	return;

}

void download(int sd_client, uint32_t &counter_server, uint32_t &counter_client, unsigned char* symmetric_key, unsigned char* user_uc, int user_len) {
	
	string user(reinterpret_cast<char const*>(user_uc), user_len);
	unsigned char* buf = NULL;
	unsigned char* dest_buffer = NULL;
	dest_buffer = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!dest_buffer) {
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	dest_buffer[strlen((const char*)dest_buffer)] = '\0';
	
	if(strcmp((const char*)dest_buffer, "<error>") == 0) {
		cout << "Error occurred on client side" << endl;
		return;
	}
	
	string filename(reinterpret_cast<char const*>(dest_buffer), strlen((const char*)dest_buffer));
	
	if(filename.size() > 100) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		string error = "<error_size>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	
	if(!check_input(filename)) {
		cout << "Error occurred: wrong filename format" << endl;
		string error = "<error_format>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string confirm = "<ok>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
	}
	
	string to_read = "./Server/" + user + "/" + filename;

	FILE* fd = fopen((const char*)to_read.c_str(), "rb");
	if(!fd) {
		string response = "<error>";
		int ret = send_cipher(sd_client, (unsigned char*)response.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return;
		}
		cout << filename << " not found" << endl;
		return;
	}
	else {
		string response = "<ok>";
		int ret = send_cipher(sd_client, (unsigned char*)response.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			fclose(fd);
			cout << "Error occured: send failed" << endl;
			return;
		}
	}
	dest_buffer = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!dest_buffer) {
		fclose(fd);
		cout << "Error occurred: receive failed" << endl;
		return;
	}
	dest_buffer[strlen((const char*)dest_buffer)] = '\0';
	
	if(strcmp((const char*)dest_buffer, "<error>") == 0) {
		cout << "Error occurred on client side" << endl;
		return;
	}
	
	fseek(fd, 0, SEEK_END);
	int size = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	
	int res = 0;
	
	string size_s = to_string(size);
	int ret = send_cipher(sd_client, (unsigned char*)size_s.c_str(), counter_server, symmetric_key);
	if(ret < 0) {
		fclose(fd);
		cout << "Error occured: send failed" << endl;
		return;
	}
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
			ret = send_cipher(sd_client, (unsigned char*)buffer, counter_server, symmetric_key, size);
			if(ret < 0) {
				fclose(fd);
				cout << "Error occured: send failed" << endl;
				return;
			}
		}
		else {
			buffer[32768] = '\0';
			ret = send_cipher(sd_client, (unsigned char*)buffer, counter_server, symmetric_key, 32768);
			if(ret < 0) {
				fclose(fd);
				cout << "Error occured: send failed" << endl;
				return;
			}
		}
		dest_buffer = receive_cipher(sd_client, buf, counter_client, symmetric_key);
		if(!dest_buffer) {
			fclose(fd);
			cout << "Error occurred: receive failed" << endl;
			return;
		}
		if(strcmp("<error>", (const char*) dest_buffer) == 0) {
			counter_server = counter_server - 1;
			res = fread(buffer, 1, -32768, fd);
			continue;
		}
		size -= 32768;
		if(size <= 0) 
			break;
		
	}
	fclose(fd);
}


void Delete(int sd_client, uint32_t& counter_client, uint32_t&counter_server, unsigned char* symmetric_key, unsigned char* user_uc, int user_len) {

	string user(reinterpret_cast<char const*>(user_uc), user_len);
	unsigned char* buf = NULL;
	unsigned char* filename_buf = NULL;
	
	filename_buf = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!filename_buf) {
		cout << "Error occured: receive failed" << endl;
		return;
	}
	
	string filename(reinterpret_cast<char const*>(filename_buf), strlen((const char*)filename_buf));
	filename[filename.size()] = '\0';
	if(filename == "<error>") {
		cout << "Error occurred on client side" << endl;
		return;
	}
	
	if(filename.size() > 100) {
		cout << "Error occurred: too many characters (max 100)" << endl;
		string error = "<error_size>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	
	if(!check_input(filename)) {
		cout << "Error occurred: wrong filename format" << endl;
		string error = "<error_format>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string confirm = "<ok>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
	}
	
	string to_read = "./Server/" + user + "/" + filename;
	
	// search for the file
	FILE* fd = fopen((const char*)to_read.c_str(), "rb");
	if(!fd) {
		string confirm = "error1";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occured: send failed" << endl;
			return;
		}
		cout << filename << " not found" << endl;
		return;
	}
	else
		fclose(fd);
	
	// filename found: ask for confirmation
	string confirm = "found";
	int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
	if(ret < 0) {
		cout << "Error occured: send failed" << endl;
		return;
	}
	
	unsigned char* confirm_response = NULL;
	confirm_response = receive_cipher(sd_client, buf, counter_client, symmetric_key);
	if(!confirm_response) {
		cout << "Error occured: receive failed" << endl;
		return;
	}
	
	string response(reinterpret_cast<char const*>(confirm_response), strlen((const char*)confirm_response));
	response[response.size()] = '\0';
	
	if(response == "error2") {
		cout << "Error occurred: invalid input" << endl;
		return;
	}
	
	if(response.size() > 1) {
		cout << "Error occurred: too many characters (max 1)" << endl;
		string error = "<error_size>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	
	if(!check_input(response)) {
		cout << "Error occurred: wrong confirm format" << endl;
		string error = "<error_format>";
		int ret = send_cipher(sd_client, (unsigned char*)error.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
		return;
	}
	else {
		string confirm = "<ok>";
		int ret = send_cipher(sd_client, (unsigned char*)confirm.c_str(), counter_server, symmetric_key);
		if(ret < 0) {
			cout << "Error occurred: send failed" << endl;
			return;
		}
	}
	
	if(response == "y") {
		int del = remove((const char*)to_read.c_str());
  	if(!del)
			cout << "The file has been removed" << endl;
  	else
    	cout << "The file has not been removed" << endl;
    return;
   }
   
   if(response == "n") {
   	cout << "The file has not been removed" << endl;
   	return;
   }
   
   cout << "Error occurred: invalid input" << endl;
}


		
		
		
		



