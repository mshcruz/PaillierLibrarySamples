#include <assert.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <gmp.h>
#include <paillier.h>


int main (int argc, char *argv[])
{
    // Security parameter (number of bits of the modulus)
    const long n = 1024;   
    
    // Generate public and secret keys
    paillier_pubkey_t* pubKey;
    paillier_prvkey_t* secKey;
    paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);
    
    // Export keys to file
    std::fstream secKeyFile("seckey.txt", std::fstream::out|std::fstream::trunc);
    std::fstream pubKeyFile("pubkey.txt", std::fstream::out|std::fstream::trunc);

    assert(secKeyFile.is_open());
    assert(pubKeyFile.is_open());	

    char* hexSecKey = paillier_prvkey_to_hex(secKey);
    char* hexPubKey = paillier_pubkey_to_hex(pubKey);    

    secKeyFile << hexSecKey;
    pubKeyFile << hexPubKey;

    secKeyFile.close();
    pubKeyFile.close();

    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
    free(hexPubKey);
    free(hexSecKey);

    return 0;
}
