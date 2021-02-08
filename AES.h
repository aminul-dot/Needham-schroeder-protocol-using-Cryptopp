#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
using namespace std;
#include <cryptopp/queue.h>
//#include "AES.h"


using namespace CryptoPP;


string aes256_encryption(string password, string message)
{
SecByteBlock key(AES::MAX_KEYLENGTH+AES::BLOCKSIZE);  //aes key size 256 and ciphertext 256.

  string encrypted, recovered;

  byte iv[ CryptoPP::AES::BLOCKSIZE ];
  memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );


  // sha256 for key generation
SHA256 hash;
hash.Update((const byte*)password.data(), password.size());
key.resize(hash.DigestSize());
hash.Final((byte*)&key[0]);

      CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
      CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );
      CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( encrypted ) );
      stfEncryptor.Put( reinterpret_cast<const unsigned char*>( message.c_str() ), message.length() );
      stfEncryptor.MessageEnd();


    return encrypted;


}

string aes256_decryption(string password, const unsigned char *encrypted, int size )
{
SecByteBlock key(AES::MAX_KEYLENGTH+AES::BLOCKSIZE);   //aes key size 256 and ciphertext 256.

  string recovered;

  byte iv[ CryptoPP::AES::BLOCKSIZE ];
  memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );


// sha256 for key generation

SHA256 hash;
hash.Update((const byte*)password.data(), password.size());
key.resize(hash.DigestSize());
hash.Final((byte*)&key[0]);
        CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );
        CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( recovered ) );
        stfDecryptor.Put(encrypted, size);
        //stfDecryptor.Put( reinterpret_cast<const unsigned char*>( encrypted.c_str() ), size() );
        stfDecryptor.MessageEnd();


return recovered;

}

string getKeyFromTicket(string ticket ,int n){

 stringstream stream(ticket);
 int i = 0;
 string word;
   while( getline(stream, word, ' ') ) {
        i++;
        if(i == n)
         {
          return word;
        }
  }
}
