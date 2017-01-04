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
    std::fstream secKeyFile("seckey.txt", std::fstream::in);    
    
    assert(pubKeyFile.is_open());
    assert(secKeyFile.is_open());    

    std::string hexPubKey;
    std::string hexSecKey;    
    std::getline(pubKeyFile, hexPubKey);
    std::getline(secKeyFile, hexSecKey);    

    pubKeyFile.close();
    secKeyFile.close();    
    
    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);

    // Read ciphertexts from file
    std::fstream ctxt1File("ciphertext1.txt", std::fstream::in|std::fstream::binary);
    std::fstream ctxt2File("ciphertext2.txt", std::fstream::in|std::fstream::binary);

    assert(ctxt1File.is_open());
    assert(ctxt2File.is_open());

    // The length of the ciphertext is twice the length of the key
    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    char* byteCtxt2 = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    ctxt1File.read(byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    ctxt2File.read(byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);    

    ctxt1File.close();
    ctxt2File.close();

    paillier_ciphertext_t* ctxt1 = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    paillier_ciphertext_t* ctxt2 = paillier_ciphertext_from_bytes((void*)byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    // Initialize the ciphertext that will hold the sum with an encryption of zero
    paillier_ciphertext_t* encryptedSum = paillier_create_enc_zero();

    // Sum the encrypted values by multiplying the ciphertexts
    paillier_mul(pubKey, encryptedSum, ctxt1, ctxt2);
    
    // Decrypt the ciphertext (sum)
    paillier_plaintext_t* dec;
    dec = paillier_dec(NULL, pubKey, secKey, encryptedSum);
    gmp_printf("Decrypted sum: %Zd\n", dec);
    
    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
    paillier_freeplaintext(dec);
    paillier_freeciphertext(ctxt1);
    paillier_freeciphertext(ctxt2);
    paillier_freeciphertext(encryptedSum);
    free(byteCtxt1);
    free(byteCtxt2);
    
    return 0;
}
