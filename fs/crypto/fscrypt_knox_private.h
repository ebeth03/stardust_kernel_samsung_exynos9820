/*
 * fscrypto_knox_private.h
 *
 *  Created on: Oct 11, 2018
 *      Author: olic.moon
 */

#ifndef FS_CRYPTO_FSCRYPT_KNOX_PRIVATE_H_
#define FS_CRYPTO_FSCRYPT_KNOX_PRIVATE_H_

#define FSCRYPT_KNOX_FLG_SDP_MASK					0xFFFF0000
#define FSCRYPT_KNOX_FLG_SDP_ENABLED             	0x00100000
#define FSCRYPT_KNOX_FLG_SDP_IS_SENSITIVE           0x00200000
#define FSCRYPT_KNOX_FLG_SDP_MULTI_ENGINE           0x00400000// eCryptfs header contains engine id.
#define FSCRYPT_KNOX_FLG_SDP_TO_SET_SENSITIVE       0x00800000
#define FSCRYPT_KNOX_FLG_SDP_TO_SET_PROTECTED       0x01000000
#define FSCRYPT_KNOX_FLG_SDP_DECRYPTED_FEK_SET      0x02000000// Be careful, this flag must be avoided to be set to xattr.
#define FSCRYPT_KNOX_FLG_SDP_IS_EMPTY_CTFM_SET      0x04000000
#define FSCRYPT_KNOX_FLG_SDP_TO_CLEAR_NONCE         0x08000000
#define FSCRYPT_KNOX_FLG_SDP_IS_CHAMBER_DIR         0x20000000
#define FSCRYPT_KNOX_FLG_SDP_IS_DIRECTORY           0x40000000
#define FSCRYPT_KNOX_FLG_SDP_IS_PROTECTED           0x80000000

struct fscrypt_context;

int dd_test_and_inherit_context(
		struct fscrypt_context *ctx,
		struct inode *parent, struct inode *child,
		struct fscrypt_info *ci, void *fs_data);

void *dd_get_info(const struct inode *inode);

void fscrypt_dd_set_count(long count);
long fscrypt_dd_get_count(void);
void fscrypt_dd_inc_count(void);
void fscrypt_dd_dec_count(void);
int fscrypt_dd_is_locked(void);

#endif /* FS_CRYPTO_FSCRYPT_KNOX_PRIVATE_H_ */
