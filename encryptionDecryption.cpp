#include <gmp.h>
#include <paillier.h>


int main(int argc, char *argv[])
{
    // Security parameter (number of bits of the modulus)
    const long n = 256;   
    
    // Generate public and secret keys
    paillier_pubkey_t* pubKey;
    paillier_prvkey_t* secKey;
    paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);

    // Plaintext initialization
    paillier_plaintext_t* m;
    m = paillier_plaintext_from_ui(2);
    gmp_printf("Plaintext: %Zd\n", m);

    // Encrypt the message
    paillier_ciphertext_t* ctxt;
    ctxt = paillier_enc(NULL, pubKey, m, paillier_get_rand_devurandom);
    gmp_printf("Ciphertext: %Zd\n", ctxt);

    // Decrypt the ciphertext
    paillier_plaintext_t* dec;
    dec = paillier_dec(NULL, pubKey, secKey, ctxt);
    gmp_printf("Decrypted: %Zd\n", dec);

    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
    paillier_freeplaintext(m);
    paillier_freeplaintext(dec);
    paillier_freeciphertext(ctxt);
    
    return 0;
}
