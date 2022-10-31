//Authors: Vera Tykesson Borvinski, Dimitar Valkov, Duke Woy, Pengfeng Luo, Sheik Mahamud
//Matriculation numbers: 2421818, 2413179, 2418150, 2458646

//include necessary libraries
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include "authlib.h"
#include <fstream>
#include <openssl/evp.h>

using namespace std;

//hash function: https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
//originally returned bool, now returns string
/**
 * Uses openssl to hash password in sha-256
 *
 * @param string, unhashed password
 * @return string, hashed password
 */
string sha256(const string unhashed)
{

    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if(context != NULL)
    {
        if(EVP_DigestInit_ex(context, EVP_sha256(), NULL))
        {
            if(EVP_DigestUpdate(context, unhashed.c_str(), unhashed.length()))
            {
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int lengthOfHash = 0;

                if(EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    std::stringstream ss;
                    for(unsigned int i = 0; i < lengthOfHash; ++i)
                    {
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }

                    return ss.str();
                }
            }
        }

        EVP_MD_CTX_free(context);
    }

    return "";
}

/**
 * Checks login details
 *
 * @param string username
 * @return bool, if login was processed
 */
bool login(string username){

	string password, file, line;

	//ask user for login info
	cout << "enter password" << endl, cin >> password;
	cout << "enter file" << endl, cin >> file;	
	
	//hash password
	string h_password = sha256(password);
	
	//format username and password like in password file
	string pair = username + ":" + h_password;
	
	//open password file and read from it
	ifstream Inputfile (file);
	if ( Inputfile.is_open() ) {
	//reading from a file line by line: https://stackoverflow.com/questions/12463750/c-searching-text-file-for-a-particular-string-and-returning-the-line-number-wh
		while(getline(Inputfile, line)) {
			//return true if value pair was found
	    		if (line.find(pair, 0) != string::npos) return true;
	    	}
	}
	//if user password pair were not in the file, return false
	return false;
}

/**
 * Main function
 */
int main() {

	string username;
	//prompts user to enter username
	cout << "enter username" << endl, cin >> username;
	//authenticate user if they were successfully logged in, reject otherwise
  	login(username) ? authenticated(username) : rejected(username);
}


