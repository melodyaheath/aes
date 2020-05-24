#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "aes.hpp"
#include <vector>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace crypto;

vector<u8> encrypt(vector<u8> plaintext, vector<u8> key, vector<u8> iv)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    vector<u8> ciphertext(32, 0);
    /* Create and initialise the context */
    EXPECT_EQ(false, (!(ctx = EVP_CIPHER_CTX_new())));
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    EXPECT_EQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), iv.data()));

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    EXPECT_EQ(1, EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()));

    /*  
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */

    int temp = 0;
    EXPECT_EQ(1, EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &temp));

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    /*
    * Create a new vector to return. Unfortunately using Envelope stores an extra 16
    * bytes at the end of the message and what I really need is just the first 16 bytes
    * which represents one block of AES 
    */
    return vector<u8>(ciphertext.begin(), ciphertext.begin() + len);
}



TEST (AesTests, libopenssl_works_as_expected) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    const vector<u8> message =   { 0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F };
    const vector<u8> key = { 0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75 };
    const vector<u8> iv(16, 0);
    const vector<u8> tested = encrypt(message, key, iv);
    const vector<u8> expected = {0x29, 0xc3, 0x50, 0x5f, 0x57, 0x14, 0x20, 0xf6, 0x40, 0x22, 0x99, 0xb3, 0x1a, 0x2, 0xd7, 0x3a};

    ASSERT_THAT(tested, testing::ElementsAreArray(expected));

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

TEST (AesTests, verify_fixed_aes_message) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    const vector<u8> message =   { 0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F };
    const vector<u8> key = { 0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75 };
    const vector<u8> iv(16, 0);
    const vector<u8> tested = (new Aes<128>())->encrypt(key,message);
    const vector<u8> expected = encrypt(message, key, iv);

    ASSERT_THAT(tested, testing::ElementsAreArray(expected));


    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

TEST (AesTests, verify_random_aes_keys) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    const vector<u8> iv(16, 0);
    const auto aes_lib = new Aes<128>();
    for ( auto test_count = 0; test_count < 1000; test_count++ ) {
        vector<u8> message(16, 0);
        vector<u8> key(16, 0);

        EXPECT_EQ(1,RAND_bytes(message.data(), 16));
        EXPECT_EQ(1,RAND_bytes(key.data(), 16));
        
        const vector<u8> expected = encrypt(message, key, iv);
        const vector<u8> tested = aes_lib->encrypt(key,message);

        ASSERT_THAT(tested, testing::ElementsAreArray(expected));

    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}