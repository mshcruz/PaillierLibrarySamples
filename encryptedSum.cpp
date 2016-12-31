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

    // Plaintexts initialization
    paillier_plaintext_t* m1;
    m1 = paillier_plaintext_from_ui(2);
    paillier_plaintext_t* m2;
    m2 = paillier_plaintext_from_ui(3);
    gmp_printf("Plaintexts: m1=%Zd, m2=%Zd\n", m1, m2);

    // Encrypt the messages
    paillier_ciphertext_t* ctxt1;
    ctxt1 = paillier_enc(NULL, pubKey, m1, paillier_get_rand_devurandom);
    paillier_ciphertext_t* ctxt2;
    ctxt2 = paillier_enc(NULL, pubKey, m2, paillier_get_rand_devurandom);
    gmp_printf("Ciphertexts: ctxt1=%Zd, ctxt2=%Zd\n", ctxt1, ctxt2);

    // Initialize the ciphertext that will hold the sum with an encryption of zero
    paillier_ciphertext_t* encrypted_sum = paillier_create_enc_zero();

    // Sum the encrypted values by multiplying the ciphertexts
    paillier_mul(pubKey, encrypted_sum, ctxt1, ctxt2);
    gmp_printf("Sum's ciphertext: %Zd\n", encrypted_sum);
    
    // Decrypt the ciphertext (sum)
    paillier_plaintext_t* dec;
    dec = paillier_dec(NULL, pubKey, secKey, encrypted_sum);
    gmp_printf("Decrypted: %Zd\n", dec);

    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
    paillier_freeplaintext(m1);
    paillier_freeplaintext(m2);    
    paillier_freeplaintext(dec);
    paillier_freeciphertext(ctxt1);
    paillier_freeciphertext(ctxt2);
    paillier_freeciphertext(encrypted_sum);
    
    return 0;
}
