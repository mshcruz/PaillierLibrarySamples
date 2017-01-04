#include <assert.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <gmp.h>
#include <paillier.h>
#include <string>

int main (int argc, char *argv[])
{
    // Read public key from disk and initialize it
    std::fstream pubKeyFile("pubkey.txt", std::fstream::in);    

    assert(pubKeyFile.is_open());

    std::string hexPubKey;    
    std::getline(pubKeyFile, hexPubKey);

    pubKeyFile.close();
    
    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);

    // Read messages from disk
    std::fstream message1File("message1.txt", std::fstream::in);
    std::fstream message2File("message2.txt", std::fstream::in);

    assert(message1File.is_open());
    assert(message2File.is_open());

    std::string message1;
    std::string message2;
    std::getline(message1File, message1);
    std::getline(message2File, message2);

    message1File.close();
    message2File.close();

    std::cout << "Message 1: " << message1 << std::endl;
    std::cout << "Message 2: " << message2 << std::endl;    

    {
	// Create plaintext objects from imported messages
	paillier_plaintext_t* ptxt1 = paillier_plaintext_from_ui(std::atoi(message1.c_str()));
	paillier_plaintext_t* ptxt2 = paillier_plaintext_from_ui(std::atoi(message2.c_str()));
	
	gmp_printf("Plaintext1 object created: %Zd\n", ptxt1);
	gmp_printf("Plaintext2 object created: %Zd\n", ptxt2);	

	// Write plaintexts to disk
	std::fstream ptxt1File("binPlaintext1.txt", std::fstream::out|std::fstream::trunc|std::fstream::binary);
	std::fstream ptxt2File("binPlaintext2.txt", std::fstream::out|std::fstream::trunc|std::fstream::binary);

	assert(ptxt1File.is_open());
	assert(ptxt2File.is_open());

	// The length of the ciphertext is twice the length of the key
	char* bytePtxt1 = (char*)paillier_plaintext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ptxt1);
	char* bytePtxt2 = (char*)paillier_plaintext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ptxt2);

	ptxt1File.write(bytePtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
	ptxt2File.write(bytePtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);    
    
	ptxt1File.close();
	ptxt2File.close();

	// Cleaning up
	paillier_freeplaintext(ptxt1);
	paillier_freeplaintext(ptxt2);
	free(bytePtxt1);
	free(bytePtxt2);
    }

    /* READING PHASE*/
    {
    // Read plaintext from disk
    std::fstream ptxt1File("binPlaintext1.txt", std::fstream::in|std::fstream::binary);
    std::fstream ptxt2File("binPlaintext2.txt", std::fstream::in|std::fstream::binary);

    assert(ptxt1File.is_open());
    assert(ptxt2File.is_open());

    // The length of the ciphertext is twice the length of the key
    char* bytePtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    char* bytePtxt2 = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    ptxt1File.read(bytePtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    ptxt2File.read(bytePtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);    

    ptxt1File.close();
    ptxt2File.close();

    paillier_plaintext_t* ptxt1 = paillier_plaintext_from_bytes((void*)bytePtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    paillier_plaintext_t* ptxt2 = paillier_plaintext_from_bytes((void*)bytePtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    gmp_printf("Plaintext1 object read: %Zd\n", ptxt1);
    gmp_printf("Plaintext2 object read: %Zd\n", ptxt2);    
	
    // Cleaning up
    paillier_freeplaintext(ptxt1);
    paillier_freeplaintext(ptxt2);
    free(bytePtxt1);
    free(bytePtxt2);    
    }    
    
    // Cleaning up
    paillier_freepubkey(pubKey);
    
    return 0;
}
