#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include "authlib.h"
#include <openssl/sha.h>

using namespace std;

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool login(string fileInput, string username, string password){
	
	string h_password=sha256(password);
	string pair;
	string = pair + ":" + h_password;
	string line;
	ifstream Inputfile;
	Inputfile.open(fileInput);
	if ( Inputfile.is_open() ) {
	//reading from a file https://stackoverflow.com/questions/12463750/c-searching-text-file-for-a-particular-string-and-returning-the-line-number-wh
	unsigned int curLine = 0;
	while(getline(Inputfile, line)) {
		curLine++;
    		if (line.find(pair, 0) != string::npos) {
        		return true;
    		}
    	}
    	return false;
}
	
	

}
int main() {
  bool auth = true;
  string username="alice";
  string password="mushroom";
  
  auth=login("password.txt",username, password);
  
  if (auth) authenticated("user");
  else rejected("user");
}
