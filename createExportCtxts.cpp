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

    // Encrypt messages
    paillier_plaintext_t* m1 = paillier_plaintext_from_ui(std::atoi(message1.c_str()));
    paillier_plaintext_t* m2 = paillier_plaintext_from_ui(std::atoi(message2.c_str()));

    paillier_ciphertext_t* ctxt1;
    paillier_ciphertext_t* ctxt2;    
    ctxt1 = paillier_enc(NULL, pubKey, m1, paillier_get_rand_devurandom);
    ctxt2 = paillier_enc(NULL, pubKey, m2, paillier_get_rand_devurandom);

    gmp_printf("ctxt1: %Zd\n", ctxt1);

    // Write ciphertexts to disk
    std::fstream ctxt1File("ciphertext1.txt", std::fstream::out|std::fstream::trunc|std::fstream::binary);
    std::fstream ctxt2File("ciphertext2.txt", std::fstream::out|std::fstream::trunc|std::fstream::binary);

    assert(ctxt1File.is_open());
    assert(ctxt2File.is_open());

    // The length of the ciphertext is twice the length of the key
    char* byteCtxt1 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt1);
    char* byteCtxt2 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt2);

    ctxt1File.write(byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    ctxt2File.write(byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);    
    
    ctxt1File.close();
    ctxt2File.close();

    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeplaintext(m1);
    paillier_freeplaintext(m2);
    paillier_freeciphertext(ctxt1);
    paillier_freeciphertext(ctxt2);
    free(byteCtxt1);
    free(byteCtxt2);
    
    return 0;
}
