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

bool login(string fileInput, string username, string password){
	
	string h_password=sha256(password);
	string pair = username + ":" + h_password;
	string line;
	ifstream Inputfile (fileInput);
	if (Inputfile.is_open()) {
	//reading from a file https://stackoverflow.com/questions/12463750/c-searching-text-file-for-a-particular-string-and-returning-the-line-number-wh
	unsigned int curLine = 0;
		while(getline(Inputfile, line)) {
			curLine++;
	    		if (line.find(pair, 0) != string::npos) {
				return true;
	    		}
	    	}
    	}
    	return false;
}	

int main() {
  bool auth = true;
  string username="alice";
  string password="mushroom";
  
  auth=login("passwords.txt",username, password);
  
  if (auth) authenticated(username);
  else rejected(username);
  return 0;
}


