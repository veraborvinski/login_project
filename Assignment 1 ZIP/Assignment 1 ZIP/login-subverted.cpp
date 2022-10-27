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
string sha256(const string unhashed, bool &x)
{

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    
    //this is to check whether password is mistaken as new line
    if(unhashed == "\n") {
	    	x = true;
	}

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

bool login(string username){

	string password, file, line;

	cout << "enter password" << endl, cin >> password;
	cout << "enter file" << endl, cin >> file;
	bool x = false;

	string h_password = sha256(password, x);
	string pair = username + ":" + h_password;
	ifstream Inputfile (file);
	if ( Inputfile.is_open() ) {
	//reading from a file https://stackoverflow.com/questions/12463750/c-searching-text-file-for-a-particular-string-and-returning-the-line-number-wh
		while(getline(Inputfile, line)) {
	    		if (line.find(pair, 0) != string::npos || (line.find(username, 0) != string::npos && x)) return true;
	    	}
	}
	return false;
}

int main() {

	string username;
	cout << "enter username" << endl, cin >> username;
  	login(username) ? authenticated(username) : rejected(username);
}

