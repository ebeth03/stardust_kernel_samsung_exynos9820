/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fscrypt.h: declarations for per-file encryption
 *
 * Filesystems that implement per-file encryption include this header
 * file with the __FS_HAS_ENCRYPTION set according to whether that filesystem
 * is being built with encryption support or not.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 */
#ifndef _LINUX_FSCRYPT_H
#define _LINUX_FSCRYPT_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/dcache.h>
#include <crypto/skcipher.h>
#include <uapi/linux/fs.h>
#include <crypto/diskcipher.h>

#define FS_CRYPTO_BLOCK_SIZE		16

#ifndef __FS_HAS_ENCRYPTION
#define __FS_HAS_ENCRYPTION (IS_ENABLED(CONFIG_EXT4_FS_ENCRYPTION) ||	\
			IS_ENABLED(CONFIG_F2FS_FS_ENCRYPTION) ||	\
			IS_ENABLED(CONFIG_UBIFS_FS_ENCRYPTION))
#endif

#define FS_CRYPTO_BLOCK_SIZE		16

struct fscrypt_ctx;

struct fscrypt_info;

struct fscrypt_str {
	unsigned char *name;
	u32 len;
};

struct fscrypt_name {
	const struct qstr *usr_fname;
	struct fscrypt_str disk_name;
	u32 hash;
	u32 minor_hash;
	struct fscrypt_str crypto_buf;
};

#define FSTR_INIT(n, l)		{ .name = n, .len = l }
#define FSTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define fname_name(p)		((p)->disk_name.name)
#define fname_len(p)		((p)->disk_name.len)

/* device unit number for iv sector */
#define FSCRYPT_DUN(i,pg_index) \
	((((i)->i_ino & 0xffffffff) << 32) | ((pg_index) & 0xffffffff))
#define FSCRYPT_PG_DUN(i,p)	FSCRYPT_DUN(i, (p)->index)

/* Maximum value for the third parameter of fscrypt_operations.set_context(). */
#define FSCRYPT_SET_CONTEXT_MAX_SIZE	28

#if __FS_HAS_ENCRYPTION
#include <linux/fscrypt_supp.h>
#else
#include <linux/fscrypt_notsupp.h>
#endif

/**
 * fscrypt_require_key - require an inode's encryption key
 * @inode: the inode we need the key for
 *
 * If the inode is encrypted, set up its encryption key if not already done.
 * Then require that the key be present and return -ENOKEY otherwise.
 *
 * No locks are needed, and the key will live as long as the struct inode --- so
 * it won't go away from under you.
 *
 * Return: 0 on success, -ENOKEY if the key is missing, or another -errno code
 * if a problem occurred while setting up the encryption key.
 */
static inline int fscrypt_require_key(struct inode *inode)
{
	if (IS_ENCRYPTED(inode)) {
		int err = fscrypt_get_encryption_info(inode);

		if (err)
			return err;
		if (!fscrypt_has_encryption_key(inode))
			return -ENOKEY;
	}
	return 0;
}

/**
 * fscrypt_prepare_link - prepare to link an inode into a possibly-encrypted directory
 * @old_dentry: an existing dentry for the inode being linked
 * @dir: the target directory
 * @dentry: negative dentry for the target filename
 *
 * A new link can only be added to an encrypted directory if the directory's
 * encryption key is available --- since otherwise we'd have no way to encrypt
 * the filename.  Therefore, we first set up the directory's encryption key (if
 * not already done) and return an error if it's unavailable.
 *
 * We also verify that the link will not violate the constraint that all files
 * in an encrypted directory tree use the same encryption policy.
 *
 * Return: 0 on success, -ENOKEY if the directory's encryption key is missing,
 * -EPERM if the link would result in an inconsistent encryption policy, or
 * another -errno code.
 */
static inline int fscrypt_prepare_link(struct dentry *old_dentry,
				       struct inode *dir,
				       struct dentry *dentry)
{
	if (IS_ENCRYPTED(dir))
		return __fscrypt_prepare_link(d_inode(old_dentry), dir);
	return 0;
}

/**
 * fscrypt_prepare_rename - prepare for a rename between possibly-encrypted directories
 * @old_dir: source directory
 * @old_dentry: dentry for source file
 * @new_dir: target directory
 * @new_dentry: dentry for target location (may be negative unless exchanging)
 * @flags: rename flags (we care at least about %RENAME_EXCHANGE)
 *
 * Prepare for ->rename() where the source and/or target directories may be
 * encrypted.  A new link can only be added to an encrypted directory if the
 * directory's encryption key is available --- since otherwise we'd have no way
 * to encrypt the filename.  A rename to an existing name, on the other hand,
 * *is* cryptographically possible without the key.  However, we take the more
 * conservative approach and just forbid all no-key renames.
 *
 * We also verify that the rename will not violate the constraint that all files
 * in an encrypted directory tree use the same encryption policy.
 *
 * Return: 0 on success, -ENOKEY if an encryption key is missing, -EPERM if the
 * rename would cause inconsistent encryption policies, or another -errno code.
 */
static inline int fscrypt_prepare_rename(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry,
					 unsigned int flags)
{
	if (IS_ENCRYPTED(old_dir) || IS_ENCRYPTED(new_dir))
		return __fscrypt_prepare_rename(old_dir, old_dentry,
						new_dir, new_dentry, flags);
	return 0;
}

/**
 * fscrypt_prepare_lookup - prepare to lookup a name in a possibly-encrypted directory
 * @dir: directory being searched
 * @dentry: filename being looked up
 * @flags: lookup flags
 *
 * Prepare for ->lookup() in a directory which may be encrypted.  Lookups can be
 * done with or without the directory's encryption key; without the key,
 * filenames are presented in encrypted form.  Therefore, we'll try to set up
 * the directory's encryption key, but even without it the lookup can continue.
 *
 * To allow invalidating stale dentries if the directory's encryption key is
 * added later, we also install a custom ->d_revalidate() method and use the
 * DCACHE_ENCRYPTED_WITH_KEY flag to indicate whether a given dentry is a
 * plaintext name (flag set) or a ciphertext name (flag cleared).
 *
 * Return: 0 on success, -errno if a problem occurred while setting up the
 * encryption key
 */
static inline int fscrypt_prepare_lookup(struct inode *dir,
					 struct dentry *dentry,
					 unsigned int flags)
{
	if (IS_ENCRYPTED(dir))
		return __fscrypt_prepare_lookup(dir, dentry);
	return 0;
}

/**
 * fscrypt_prepare_setattr - prepare to change a possibly-encrypted inode's attributes
 * @dentry: dentry through which the inode is being changed
 * @attr: attributes to change
 *
 * Prepare for ->setattr() on a possibly-encrypted inode.  On an encrypted file,
 * most attribute changes are allowed even without the encryption key.  However,
 * without the encryption key we do have to forbid truncates.  This is needed
 * because the size being truncated to may not be a multiple of the filesystem
 * block size, and in that case we'd have to decrypt the final block, zero the
 * portion past i_size, and re-encrypt it.  (We *could* allow truncating to a
 * filesystem block boundary, but it's simpler to just forbid all truncates ---
 * and we already forbid all other contents modifications without the key.)
 *
 * Return: 0 on success, -ENOKEY if the key is missing, or another -errno code
 * if a problem occurred while setting up the encryption key.
 */
static inline int fscrypt_prepare_setattr(struct dentry *dentry,
					  struct iattr *attr)
{
	if (attr->ia_valid & ATTR_SIZE)
		return fscrypt_require_key(d_inode(dentry));
	return 0;
}

/**
 * fscrypt_prepare_symlink - prepare to create a possibly-encrypted symlink
 * @dir: directory in which the symlink is being created
 * @target: plaintext symlink target
 * @len: length of @target excluding null terminator
 * @max_len: space the filesystem has available to store the symlink target
 * @disk_link: (out) the on-disk symlink target being prepared
 *
 * This function computes the size the symlink target will require on-disk,
 * stores it in @disk_link->len, and validates it against @max_len.  An
 * encrypted symlink may be longer than the original.
 *
 * Additionally, @disk_link->name is set to @target if the symlink will be
 * unencrypted, but left NULL if the symlink will be encrypted.  For encrypted
 * symlinks, the filesystem must call fscrypt_encrypt_symlink() to create the
 * on-disk target later.  (The reason for the two-step process is that some
 * filesystems need to know the size of the symlink target before creating the
 * inode, e.g. to determine whether it will be a "fast" or "slow" symlink.)
 *
 * Return: 0 on success, -ENAMETOOLONG if the symlink target is too long,
 * -ENOKEY if the encryption key is missing, or another -errno code if a problem
 * occurred while setting up the encryption key.
 */
static inline int fscrypt_prepare_symlink(struct inode *dir,
					  const char *target,
					  unsigned int len,
					  unsigned int max_len,
					  struct fscrypt_str *disk_link)
{
	if (IS_ENCRYPTED(dir) || fscrypt_dummy_context_enabled(dir))
		return __fscrypt_prepare_symlink(dir, len, max_len, disk_link);

	disk_link->name = (unsigned char *)target;
	disk_link->len = len + 1;
	if (disk_link->len > max_len)
		return -ENAMETOOLONG;
	return 0;
}

/**
 * fscrypt_encrypt_symlink - encrypt the symlink target if needed
 * @inode: symlink inode
 * @target: plaintext symlink target
 * @len: length of @target excluding null terminator
 * @disk_link: (in/out) the on-disk symlink target being prepared
 *
 * If the symlink target needs to be encrypted, then this function encrypts it
 * into @disk_link->name.  fscrypt_prepare_symlink() must have been called
 * previously to compute @disk_link->len.  If the filesystem did not allocate a
 * buffer for @disk_link->name after calling fscrypt_prepare_link(), then one
 * will be kmalloc()'ed and the filesystem will be responsible for freeing it.
 *
 * Return: 0 on success, -errno on failure
 */
static inline int fscrypt_encrypt_symlink(struct inode *inode,
					  const char *target,
					  unsigned int len,
					  struct fscrypt_str *disk_link)
{
	if (IS_ENCRYPTED(inode))
		return __fscrypt_encrypt_symlink(inode, target, len, disk_link);
	return 0;
}

/* inline.c */
#define fscrypt_set_bio_cryptd(inode, bio) fscrypt_set_bio_cryptd_dun(inode, bio, 0)

static inline void fscrypt_set_bio_cryptd_dun(const struct inode *inode, struct bio *bio, u64 dun)
{
}

static inline void *fscrypt_get_bio_cryptd(const struct inode *inode)
{
	return NULL;
}

static inline int fscrypt_inline_encrypted(const struct inode *inode)
{
	return 0;
}

static inline int fscrypt_submit_bh(int op, int op_flags, struct buffer_head *bh, struct inode *inode)
{
	return -EOPNOTSUPP;
}

static inline unsigned long long __fscrypt_make_dun(const struct inode *inode, pgoff_t pg_idx)
{
	return 0;
}

#endif	/* _LINUX_FSCRYPT_H */
