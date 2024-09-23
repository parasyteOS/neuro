#include <linux/string.h>
#include <linux/scatterlist.h>
#include <crypto/akcipher.h>

#include "log.h"
#include "ecdsa.h"

static u8 *pub_key;
static u32 pub_key_len = -1;

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_decode(const char *src, int srclen, u8 *dst)
{
	u32 ac = 0;
	int bits = 0;
	int i;
	u8 *bp = dst;

	for (i = 0; i < srclen; i++) {
		const char *p = strchr(base64_table, src[i]);

		if (src[i] == '=') {
			ac = (ac << 6);
			bits += 6;
			if (bits >= 8)
				bits -= 8;
			continue;
		}
		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (u8)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

int ecdsa_verify_signature(u8 *digest, u32 digest_size,
		     u8 *signature, u32 signature_size)
{
	struct crypto_wait cwait;
	struct crypto_akcipher *tfm;
	struct akcipher_request *req;
	struct scatterlist src_sg[2];
	int rc = -EINVAL;

	pr_info("ecdsa_verify_signature: digest_size: %d, signature_size: %d", digest_size, signature_size);

	if (pub_key_len < 0) {
		pr_err("public key not loaded.");
		return rc;
	}

	tfm = crypto_alloc_akcipher("ecdsa-nist-p256", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Failed to allocate akcipher: %d", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	rc = -ENOMEM;
	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto error_free_tfm;

	rc = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
	if (rc) {
		pr_err("Failed to set public key: %d", rc);
		goto error_free_req;
	}

	sg_init_table(src_sg, 2);
	sg_set_buf(&src_sg[0], signature, signature_size);
	sg_set_buf(&src_sg[1], digest, digest_size);
	akcipher_request_set_crypt(req, src_sg, NULL, signature_size,
				   digest_size);
	crypto_init_wait(&cwait);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &cwait);
	rc = crypto_wait_req(crypto_akcipher_verify(req), &cwait);
	pr_info("verify result: %d", rc);

error_free_req:
	akcipher_request_free(req);
error_free_tfm:
	crypto_free_akcipher(tfm);

	return rc;
}

int init_ecdsa(const char *pub_key_base64)
{
	size_t len = strlen(pub_key_base64);

	pub_key = kmalloc(len, GFP_KERNEL);
	if (!pub_key)
		return -ENOMEM;

	pub_key_len = base64_decode(pub_key_base64, len, pub_key);
	if (pub_key_len < 0) {
		kfree(pub_key);
		return pub_key_len;
	}

	return 0;
}
