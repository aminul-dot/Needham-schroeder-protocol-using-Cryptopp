# Needham-schroeder-protocol-using-Cryptopp-Library

# Implement Needham-Schroeder Protocol. Used three physical computers for three different roles:- 
i) Initiator (Alice), 
ii) Responder (Bob) and 
iii) KDC.

1. First Install crypto++ library
2. Run ./KDC.sh
3. Run ./Bob.sh
4. Run ./Alice.sh
5. All the username and passwords stored in Data.csv


# Installation Crypto++ library

1- Open your terminal

2- run the following commands:

 sudo apt-get update
 sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils

3- congrat, you have intsalled crypto++ on your ubuntu

4- now, for the AES.cpp example

6- now, open your terminal and go to the directory where u have stored the program

7- now type the following command:

 g++ AES.cpp -o AesOutput -lcryptopp

8- now write the following: ./AesOutput




