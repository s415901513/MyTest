#include <openssl/evp.h>
#include <iostream>

int main() {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	char message[] = "Hello, world!";
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname("sha256");

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, digest, &digest_len);
	EVP_MD_CTX_free(mdctx);

	std::cout << "SHA256 digest: ";
	for (unsigned int i = 0; i < digest_len; i++) {
		printf("%02x", digest[i]);
	}
	std::cout << std::endl;

	return 0;
}
