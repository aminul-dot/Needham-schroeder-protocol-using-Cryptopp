#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/queue.h>

#include "AES.h"

using namespace std;
using namespace CryptoPP;


char sKey[10];
string getPassword(string);

int start_server(int);
int start_listen_client(int );
void checkError(int);


struct  sData
{
    char user1[15];
    char user2[15];
    int r ;

};

void generateTicket(){
	int i = 0;
	std::srand(std::time(NULL));

	for(i = 0 ; i <= 8; i++){
		sKey[i] = 65+rand()%26;
	}
	sKey[8] = '\0';
	printf("%s\n", sKey);
}

int x=0;

int main(int argc, char* argv[]) {

	int sockfd, clientAlice;
	sData u;

	//printf("%d\n%d", sizeof(aliceT),sizeof(byte));

	//sockfd start_server(argv[1]);

	sockfd = start_server(6001);

		for(int x = 0; x < 10; x++){
	clientAlice = start_listen_client(sockfd);

	checkError(read(clientAlice,&u,sizeof(u)));
	generateTicket();
	cout<<"----------"<<u.user1<<" want to communicate with "<<u.user2<<endl;
  cout<<"----------Recieved Nonce Value "<<u.r<<endl;


	// bob ticket

	string Bticket;
	Bticket +=string(u.user1);
	Bticket +=" ";
	Bticket +=string(sKey);

	string BobPass;
	string AlicePass;

	AlicePass = getPassword(u.user1);
	BobPass = getPassword(u.user2);

	cout<<" ----------Alice password----------"<<AlicePass<<endl;
	cout<<"----------Bob password----------"<<BobPass<<endl;
	cout<<"----------Bob ticket----------"<<Bticket<<endl;

	string BticketEn = aes256_encryption(BobPass,Bticket);

	// Encrypted text (Ra + Bob + kssn + ticket bob)

	string Aticket ;

	Aticket+=to_string(u.r);
	Aticket+=" ";
	Aticket+=string(u.user2);
	Aticket+=" ";
	Aticket+=string(sKey);
  Aticket+=" ";
  Aticket+= BticketEn;

	string AticketEn = aes256_encryption(AlicePass,Aticket);

	char At[120];
	char Bt[120];
	sprintf(At,"%s",AticketEn.data());
	//strcpy(At,AticketEn.data());
	//strcpy(Bt,BticketEn.data());
	int lenA = AticketEn.size();

	const unsigned char *chA =(reinterpret_cast<const unsigned char*> (AticketEn.c_str()));
	//const unsigned char *chB =(reinterpret_cast<const unsigned char*> (BticketEn.c_str()));

	cout<<"---------Encrypted Message-------"<<aes256_decryption(AlicePass,chA,AticketEn.size())<<endl;

	cout<<AticketEn.size();

	checkError(write(clientAlice,&lenA,sizeof(int)));
	checkError(write(clientAlice,chA,AticketEn.size()));
}


    return 0;
	}



int start_server(int port_no){

   int sockfd;
   struct sockaddr_in serv_addr;

   // socket function
   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd < 0) {
      perror("ERROR opening socket");
      return -1;
      //exit(1);
   }
   /* Initialize socket structure */
   if(port_no==0){
      port_no = 8001;
   }

   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(port_no);

   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
      return -1;
      //exit(1);
   }

   return sockfd;
}



int start_listen_client(int sockfd){

   int client_con;
   struct sockaddr_in cli_addr;
   socklen_t clilen;


   listen(sockfd,5);
   clilen = sizeof(cli_addr);

   /* Accept actual connection from the client */
   client_con = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);

   if (client_con < 0) {
      perror("ERROR on accept");
      return -1;
   }

   return client_con;

}



void checkError(int n){
   if(n < 0){
      perror("Error in read/write opration");
      exit(1);
   }
}


string getPassword(string username)
{
      int i=0;
      int j=0;
      std::ifstream file("data.csv");
      std::string plaintext;
      std::string main1;
      main1=",incorrect username";
      std::string word;
       while (std::getline(file, plaintext))
       {
       //cout<<plaintext<<endl;
      stringstream stream(plaintext);
      while( getline(stream, word, ',') )
        {
        i++;
        if(i % 2 != 0)
         {
           if(username == word)
             {
            main1 = plaintext;
            //cout<<"found"<<word<<endl;
            break;
             }
         }
        }
        }

    stringstream stream(main1);
      while( getline(stream, word, ',') )
        {
        j++;
        if(j % 2 == 0)
         {
               break;
         }
        }
        return word;
    }
