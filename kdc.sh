rm kdc.out
g++ KDC.cpp -o kdc.out -l:libcryptopp.a
./kdc.out 6001
