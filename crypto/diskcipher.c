/*
 * Copyright (C) 2017 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/diskcipher.h>
#include <linux/delay.h>

#include "internal.h"

#define crypto_diskcipher_check(a) (0)
#define disckipher_log_show(a) do { } while (0)

struct crypto_diskcipher *crypto_diskcipher_get(struct bio *bio)
{
	if (!bio || !virt_addr_valid(bio)) {
		pr_err("%s: Invalid bio:%p\n", __func__, bio);
		return NULL;
	}

	if (bio->bi_opf & REQ_CRYPT) {
		if (bio->bi_cryptd) {
			if (!crypto_diskcipher_check(bio))
				return bio->bi_cryptd;
			else
				return ERR_PTR(-EINVAL);
		} else {
			crypto_diskcipher_debug(DISKC_NO_CRYPT_ERR, 0);
			return ERR_PTR(-EINVAL);
		}
	}

	return NULL;
}

void crypto_diskcipher_set(struct bio *bio,
			struct crypto_diskcipher *tfm, u64 dun)
{
	if (bio && tfm) {
		bio->bi_opf |= REQ_CRYPT;
		bio->bi_cryptd = tfm;
#ifdef CONFIG_CRYPTO_DISKCIPHER_DUN
		if (dun)
			bio->bi_iter.bi_dun = dun;
#endif
	}
	crypto_diskcipher_debug(DISKC_API_SET, 0);
}

/* debug freerq */
enum diskc_status {
	DISKC_ST_INIT,
	DISKC_ST_FREE_REQ,
	DISKC_ST_FREE,
};

int crypto_diskcipher_setkey(struct crypto_diskcipher *tfm, const char *in_key,
			     unsigned int key_len, bool persistent)
{
	struct crypto_tfm *base = crypto_diskcipher_tfm(tfm);
	struct diskcipher_alg *cra = crypto_diskcipher_alg(base->__crt_alg);

	if (!cra) {
		pr_err("%s: doesn't exist cra. base:%p", __func__, base);
		return -EINVAL;
	}

	crypto_diskcipher_debug(DISKC_API_SETKEY, 0);
	return cra->setkey(base, in_key, key_len, persistent);
}

int crypto_diskcipher_clearkey(struct crypto_diskcipher *tfm)
{
	struct crypto_tfm *base = crypto_diskcipher_tfm(tfm);
	struct diskcipher_alg *cra = crypto_diskcipher_alg(base->__crt_alg);

	if (!cra) {
		pr_err("%s: doesn't exist cra. base:%p", __func__, base);
		return -EINVAL;
	}
	return cra->clearkey(base);
}

int crypto_diskcipher_set_crypt(struct crypto_diskcipher *tfm, void *req)
{
	int ret = 0;
	struct crypto_tfm *base = crypto_diskcipher_tfm(tfm);
	struct diskcipher_alg *cra = NULL;

	if (!base) {
		pr_err("%s: doesn't exist cra. base:%p", __func__, base);
		ret = -EINVAL;
		goto out;
	}

	cra = crypto_diskcipher_alg(base->__crt_alg);

	if (!cra) {
		pr_err("%s: doesn't exist cra. base:%p\n", __func__, base);
		ret = -EINVAL;
		goto out;
	}

	if (atomic_read(&tfm->status) == DISKC_ST_FREE) {
		pr_err("%s: tfm is free\n", __func__);
		crypto_diskcipher_debug(DISKC_CRYPT_WARN, 0);
		return -EINVAL;
	}

	ret = cra->crypt(base, req);

#ifdef USE_FREE_REQ
	if (!list_empty(&cra->freectrl.freelist)) {
		if (!atomic_read(&cra->freectrl.freewq_active)) {
			atomic_set(&cra->freectrl.freewq_active, 1);
			schedule_delayed_work(&cra->freectrl.freewq, 0);
		}
	}
#endif
out:
	if (ret)
		pr_err("%s fails ret:%d, cra:%p\n", __func__, ret, cra);
	crypto_diskcipher_debug(DISKC_API_CRYPT, ret);
	return ret;
}

int crypto_diskcipher_clear_crypt(struct crypto_diskcipher *tfm, void *req)
{
	int ret = 0;
	struct crypto_tfm *base = crypto_diskcipher_tfm(tfm);
	struct diskcipher_alg *cra = NULL;

	if (!base) {
		pr_err("%s: doesn't exist base, tfm:%p\n", __func__, tfm);
		ret = -EINVAL;
		goto out;
	}

	cra = crypto_diskcipher_alg(base->__crt_alg);

	if (!cra) {
		pr_err("%s: doesn't exist cra. base:%p\n", __func__, base);
		ret = -EINVAL;
		goto out;
	}

	if (atomic_read(&tfm->status) == DISKC_ST_FREE) {
		pr_warn("%s: tfm is free\n", __func__);
		return -EINVAL;
	}

	ret = cra->clear(base, req);
	if (ret)
		pr_err("%s fails", __func__);

out:
	crypto_diskcipher_debug(DISKC_API_CLEAR, ret);
	return ret;
}

#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
int diskcipher_do_crypt(struct crypto_diskcipher *tfm,
			struct diskcipher_test_request *req)
{
	int ret;
	struct crypto_tfm *base = crypto_diskcipher_tfm(tfm);
	struct diskcipher_alg *cra = crypto_diskcipher_alg(base->__crt_alg);

	if (!cra) {
		pr_err("%s: doesn't exist cra. base:%p\n", __func__, base);
		ret = -EINVAL;
		goto out;
	}

	if (cra->do_crypt)
		ret = cra->do_crypt(base, req);
	else
		ret = -EINVAL;
	if (ret)
		pr_err("%s fails ret:%d", __func__, ret);

out:
	return ret;
}
#endif

static int crypto_diskcipher_init_tfm(struct crypto_tfm *base)
{
	struct crypto_diskcipher *tfm = __crypto_diskcipher_cast(base);

	atomic_set(&tfm->status, DISKC_ST_INIT);
	return 0;
}

#ifdef USE_FREE_REQ
static void free_workq_func(struct work_struct *work)
{
	struct diskcipher_alg *cra =
		container_of(work, struct diskcipher_alg, freectrl.freewq.work);
	struct diskcipher_freectrl *fctrl = &cra->freectrl;
	struct crypto_diskcipher *_tfm, *tmp;
	unsigned long cur_jiffies = jiffies;
	struct list_head poss_free_list;
	unsigned long flags;

	INIT_LIST_HEAD(&poss_free_list);

	/* pickup freelist */
	spin_lock_irqsave(&fctrl->freelist_lock, flags);
	list_for_each_entry_safe(_tfm, tmp, &fctrl->freelist, node) {
		if (jiffies_to_msecs(cur_jiffies - _tfm->req_jiffies) > fctrl->max_io_ms)
			list_move_tail(&_tfm->node, &poss_free_list);
	}
	spin_unlock_irqrestore(&fctrl->freelist_lock, flags);

	list_for_each_entry_safe(_tfm, tmp, &poss_free_list, node) {
		if (atomic_read (&_tfm->status) != DISKC_ST_FREE_REQ)
			crypto_diskcipher_debug(DISKC_FREE_WQ_WARN, 0);
		crypto_free_diskcipher(_tfm);
	}

	if (!list_empty(&fctrl->freelist))
		schedule_delayed_work(&fctrl->freewq, msecs_to_jiffies(fctrl->max_io_ms));
	else
		atomic_set(&fctrl->freewq_active, 0);
}
#endif

void crypto_free_req_diskcipher(struct crypto_diskcipher *tfm)
{
#ifdef USE_FREE_REQ
	struct crypto_tfm *base = crypto_diskcipher_tfm(tfm);
	struct diskcipher_alg *cra = crypto_diskcipher_alg(base->__crt_alg);
	struct diskcipher_freectrl *fctrl = &cra->freectrl;
	unsigned long flags;

	if (atomic_read(&tfm->status) != DISKC_ST_INIT) {
		crypto_diskcipher_debug(DISKC_FREE_REQ_WARN, 0);
		pr_warn("%s: already submit status:%d\n", __func__, atomic_read(&tfm->status));
		return;
	}

	atomic_set(&tfm->status, DISKC_ST_FREE_REQ);
	INIT_LIST_HEAD(&tfm->node);
	tfm->req_jiffies = jiffies;
	spin_lock_irqsave(&fctrl->freelist_lock, flags);
	list_move_tail(&tfm->node, &fctrl->freelist);
	spin_unlock_irqrestore(&fctrl->freelist_lock, flags);
	crypto_diskcipher_debug(DISKC_API_FREEREQ, 0);
#else
	crypto_free_diskcipher(tfm);
#endif
}

unsigned int crypto_diskcipher_extsize(struct crypto_alg *alg)
{
	return alg->cra_ctxsize +
	    (alg->cra_alignmask & ~(crypto_tfm_ctx_alignment() - 1));
}

static void crypto_diskcipher_show(struct seq_file *m, struct crypto_alg *alg)
{
	seq_printf(m, "type         : diskcipher\n");
	disckipher_log_show(m);
}

static const struct crypto_type crypto_diskcipher_type = {
	.extsize = crypto_diskcipher_extsize,
	.init_tfm = crypto_diskcipher_init_tfm,
#ifdef CONFIG_PROC_FS
	.show = crypto_diskcipher_show,
#endif
	.maskclear = ~CRYPTO_ALG_TYPE_MASK,
	.maskset = CRYPTO_ALG_TYPE_MASK,
	.type = CRYPTO_ALG_TYPE_DISKCIPHER,
	.tfmsize = offsetof(struct crypto_diskcipher, base),
};

#define DISKC_NAME "-disk"
#define DISKC_NAME_SIZE (5)
#define DISKCIPHER_MAX_IO_MS (1000)
struct crypto_diskcipher *crypto_alloc_diskcipher(const char *alg_name,
			u32 type, u32 mask, bool force)
{
	crypto_diskcipher_debug(DISKC_API_ALLOC, 0);
	if (force) {
		if (strlen(alg_name) + DISKC_NAME_SIZE < CRYPTO_MAX_ALG_NAME) {
			char diskc_name[CRYPTO_MAX_ALG_NAME];

			strcpy(diskc_name, alg_name);
			strcat(diskc_name, DISKC_NAME);
			return crypto_alloc_tfm(diskc_name,
				&crypto_diskcipher_type, type, mask);
		}
	} else {
		return crypto_alloc_tfm(alg_name, &crypto_diskcipher_type, type, mask);
	}
	return NULL;
}

void crypto_free_diskcipher(struct crypto_diskcipher *tfm)
{
	crypto_diskcipher_debug(DISKC_API_FREE, 0);
	atomic_set(&tfm->status, DISKC_ST_FREE);
	crypto_destroy_tfm(tfm, crypto_diskcipher_tfm(tfm));
}

int crypto_register_diskcipher(struct diskcipher_alg *alg)
{
	struct crypto_alg *base = &alg->base;

#ifdef USE_FREE_REQ
	struct diskcipher_freectrl *fctrl = &alg->freectrl;

	INIT_LIST_HEAD(&fctrl->freelist);
	INIT_DELAYED_WORK(&fctrl->freewq, free_workq_func);
	spin_lock_init(&fctrl->freelist_lock);
	if (!fctrl->max_io_ms)
		fctrl->max_io_ms = DISKCIPHER_MAX_IO_MS;
#endif
	base->cra_type = &crypto_diskcipher_type;
	base->cra_flags = CRYPTO_ALG_TYPE_DISKCIPHER;
	return crypto_register_alg(base);
}

void crypto_unregister_diskcipher(struct diskcipher_alg *alg)
{
	crypto_unregister_alg(&alg->base);
}

int crypto_register_diskciphers(struct diskcipher_alg *algs, int count)
{
	int i, ret;

	for (i = 0; i < count; i++) {
		ret = crypto_register_diskcipher(algs + i);
		if (ret)
			goto err;
	}
	return 0;

err:
	for (--i; i >= 0; --i)
		crypto_unregister_diskcipher(algs + i);
	return ret;
}

void crypto_unregister_diskciphers(struct diskcipher_alg *algs, int count)
{
	int i;

	for (i = count - 1; i >= 0; --i)
		crypto_unregister_diskcipher(algs + i);
}
