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
#include "AES.h"

using namespace std;
using namespace CryptoPP;



char sKey[10];

int start_server(int);
int start_listen_client(int );
void checkError(int);




int main(int argc, char  *argv[])
{

	cout<<"----------Waiting for conncetion----------"<<endl;

  int sockfd, clientAlice;
  sockfd = start_server(6002);
  clientAlice = start_listen_client(sockfd);


  int lenB = 16;
  unsigned char Bt[180];
  checkError(read(clientAlice,&lenB,sizeof(int)));
  checkError(read(clientAlice,Bt,lenB));
  string BobPass;
  cout<<"----------Ticket is Recived---------"<<endl;
	cout<<"----------Enter your password to Decrypt session key----------"<<endl;

  cin>>BobPass;

  //BobPass = "123456";
  string ticket = aes256_decryption(BobPass,Bt,lenB);
  cout<<"----------Here is Recived ticket----------"<<ticket<<endl;//sizeof(AT));

  string sKey = getKeyFromTicket(ticket,2);

  //cout<<"ticket = "<<sKey<<endl;//sizeof(AT));

  std::srand(std::time(NULL));
  int no;
  no =rand()%10000;

  string nonce = to_string(no);
  cout<<"----------My NONCE----------"<<nonce<<endl;;

  string Enonce = aes256_encryption(sKey,nonce);



  int lenE = Enonce.size();

  const unsigned char *chE =(reinterpret_cast<const unsigned char*> (Enonce.c_str()));

  // alice ticket
  cout<<"----------Sending Nonce----------"<<endl;
  checkError(write(clientAlice,&lenE,sizeof(int)));
  checkError(write(clientAlice,chE,Enonce.size()));


 //cout<<"recving nonce"<<endl;
  unsigned char RecEn[180];
  checkError(read(clientAlice,&lenE,sizeof(int)));
  checkError(read(clientAlice,RecEn,lenE));

  string RecN = aes256_decryption(sKey,RecEn,lenE);

  cout<<"----------Recived Nonce----------"<<RecN<<endl;
   int RNonce = stoi(RecN);
	if(no-1 == RNonce)
	{
		cout<<"--------Authentication Succesful----------"<<endl;
		checkError(write(clientAlice,"Authentication Succesful",25));
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
