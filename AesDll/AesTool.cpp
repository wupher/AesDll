#include "pch.h"
#include "AesTool.h"

#include <string>
#include "openssl/sha.h"
#include "openssl/aes.h"
#include <openssl/evp.h>
#include <cassert>

using std::string;

char* base64(const unsigned char* input, int length) {
	const auto pl = 4 * ((length + 2) / 3);
	auto output = reinterpret_cast<char*>(calloc(pl + 1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
	const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output), input, length);
	return output;
}

unsigned char* decode64(const char* input, int length) {
	const auto pl = 3 * length / 4;
	auto output = reinterpret_cast<unsigned char*>(calloc(pl + 1, 1));
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char*>(input), length);
	return output;
}


 const char* encryptAndBase64(const unsigned char* plain, const unsigned char* password)
{
	 //prepare key
	 unsigned char key[20];
	 size_t lenOfPassowrd = strlen((char *)password);
	 size_t lenOfPlain = strlen((char*)plain);
	 SHA1(password, lenOfPassowrd, key);

	 //aes128 with ecb
	 EVP_CIPHER_CTX* ctx;
	 ctx = EVP_CIPHER_CTX_new();
	 int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	 assert(ret == 1);

	 //init a buff
	 unsigned char* result = new unsigned char[lenOfPlain + 64];
	 int len1 = 0;
	 ret = EVP_EncryptUpdate(ctx, result, &len1, plain, lenOfPlain);
	 assert(ret == 1);
	 int len2 = 0;
	 ret = EVP_EncryptFinal_ex(ctx, result + len1, &len2);
	 assert(ret == 1);
	 ret = EVP_CIPHER_CTX_cleanup(ctx);
	 assert(ret == 1);
	 EVP_CIPHER_CTX_free(ctx);

	 //base64 result
	 char* baseResult = base64(result, len1 + len2);
	 return baseResult;
}

 const char* uncode64AndDecrypt(const unsigned char* plain, const unsigned char* password) {
	 size_t lenOfPlain = strlen((char*)plain);
	 size_t lenOfPwd = strlen((char*)password);
	 unsigned char* debaseCipher = decode64((char *) plain, lenOfPlain);

	 //prepare key
	 unsigned char key[20];
	 SHA1(password, lenOfPwd, key);

	 //aes128 with ecb
	 EVP_CIPHER_CTX* ctx;
	 ctx = EVP_CIPHER_CTX_new();
	 int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	 assert(ret == 1);

	 unsigned char* result = new unsigned char[lenOfPlain + 64];
	 int len1 = 0;
	 ret = EVP_DecryptUpdate(ctx, result, &len1, debaseCipher, strlen((char*)debaseCipher));
	 assert(ret == 1);
	 int len2 = 0;
	 ret = EVP_DecryptFinal_ex(ctx, result + len1, &len2);
	 assert(ret == 1);
	 ret = EVP_CIPHER_CTX_cleanup(ctx);
	 assert(ret == 1);
	 EVP_CIPHER_CTX_free(ctx);
	 return (char *)result;
}
