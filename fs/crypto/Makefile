obj-$(CONFIG_FS_ENCRYPTION)	+= fscrypto.o

fscrypto-y := crypto.o fname.o hooks.o keyinfo.o policy.o
fscrypto-$(CONFIG_BLOCK) += bio.o
fscrypto-$(CONFIG_FS_CRYPTO_SEC_EXTENSION) += crypto_sec.o
fscrypto-$(CONFIG_FS_INLINE_ENCRYPTION) += inline.o

