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

struct  sData
{
    char user1[15];
    char user2[15];
    int r ;

};

int connect_to_server(char *, int );

void checkError(int);

int main(int argc, char  *argv[])
{



	sData u;
	cout<<"----------------Enter UserName----------------"<<endl;
	cin>>u.user1;
	cout<<"-------Enter to Whom you want to connect------"<<endl;
	cin>>u.user2;
	std::srand(std::time(NULL));
	u.r=rand()%10000;
  cout<<"----------My NONCE is ----------"<<u.r<<endl;



	int KDC = connect_to_server(argv[1],6001);
	cout<<"--------------Connecting to KDC---------------"<<endl;
	checkError(write(KDC,&u,sizeof(u)));

	int lenA;
	int lenB;
	unsigned char At[180];
	unsigned char Bt[180];

	checkError(read(KDC,&lenA,sizeof(int)));
	checkError(read(KDC,At,lenA));

	//checkError(read(KDC,&lenB,sizeof(int)));
	//checkError(read(KDC,Bt,lenB));

	string BobPass;
	string AlicePass;

	cout<<"----------Enter your password to Decrypt session key----------"<<endl;
	cin>>AlicePass;
  string Aticket = aes256_decryption(AlicePass,At,lenA);
  string sKey = getKeyFromTicket(Aticket,3);
	cout<<"----------Session key----------= "<<sKey<<endl;


  string bobticket = getKeyFromTicket(Aticket,4);
  cout<<"----BOB TICKET----"<<bobticket<<endl;
  lenB = bobticket.size();
  const unsigned char *chB =(reinterpret_cast<const unsigned char*> (bobticket.c_str()));

	int BOB = connect_to_server(argv[1],6002);



	// bob ticket
	cout<<"----------Sending Ticket----------"<<endl;
	//checkError(write(BOB,&lenB,sizeof(int)));
	//checkError(write(BOB,Bt,lenB));

  checkError(write(BOB,&lenB,sizeof(int)));
	checkError(write(BOB,chB,bobticket.size()));

	cout<<"----------Ticket is sent----------"<<endl;
	//////////////



	int lenE;


	unsigned char RecEn[180];

	//cout<<"----------Reciveing Nonce----------"<<endl;

  	checkError(read(BOB,&lenE,sizeof(int)));
  	checkError(read(BOB,RecEn,lenE));

  	string nonce = aes256_decryption(sKey,RecEn,lenE);

  	cout<<"---------Recived nonce--------"<<nonce<<endl;

  	int nonceValue = atoi(nonce.c_str());
  	//cout<<nonceValue<<endl;
  	nonceValue--;

  	string NonceReturn = to_string(nonceValue);

  	string  NonceReturnE = aes256_encryption(sKey,NonceReturn);

  	const unsigned char *chE =(reinterpret_cast<const unsigned char*> (NonceReturnE.c_str()));

  	// alice ticket
    char buffer1[30];
  	cout<<"----------Sending Nonce----------"<<endl;
  	checkError(write(BOB,&lenE,sizeof(int)));
  	checkError(write(BOB,chE,NonceReturnE.size()));

  	cout<<"----------Nonce sent----------"<<endl;
    checkError(read(BOB,buffer1,30));
    cout<<buffer1<<endl;







	return 0;
}




int connect_to_server(char *server_address, int portno) {

   int sockfd;
   struct sockaddr_in serv_addr;
   struct hostent *server;

   /* Create a socket point */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) {
        perror("ERROR opening socket");
      return -1;
      //exit(1);
   }


    server = gethostbyname(server_address);

   if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      return -1;
  //    exit(0);
   }

   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);

   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR connecting");
      return -1;
  //    exit(0);
   }

  return sockfd;
}

void checkError(int n){
   if(n <= 0){
      printf("Error in read/write opration");
      exit(1);
   }
}
