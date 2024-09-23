#ifndef __TSU_H_ECDSA
#define __TSU_H_ECDSA

int ecdsa_verify_signature(u8 *digest, u32 digest_size,
			   u8 *signature, u32 signature_size);
int init_ecdsa(const char *pub_key_base64);

#endif
