// SPDX-License-Identifier: GPL-2.0-only
/*
 * In memory quota format relies on quota infrastructure to store dquot
 * information for us. While conventional quota formats for file systems
 * with persistent storage can load quota information into dquot from the
 * storage on-demand and hence quota dquot shrinker can free any dquot
 * that is not currently being used, it must be avoided here. Otherwise we
 * can lose valuable information, user provided limits, because there is
 * no persistent storage to load the information from afterwards.
 *
 * One information that in-memory quota format needs to keep track of is
 * a sorted list of ids for each quota type. This is done by utilizing
 * an rb tree which root is stored in mem_dqinfo->dqi_priv for each quota
 * type.
 *
 * This format can be used to support quota on file system without persistent
 * storage such as tmpfs.
 */
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>

#include <linux/quotaops.h>
#include <linux/quota.h>

MODULE_AUTHOR("Lukas Czerner");
MODULE_DESCRIPTION("Quota in-memory format support");
MODULE_LICENSE("GPL");

/*
 * The following constants define the amount of time given a user
 * before the soft limits are treated as hard limits (usually resulting
 * in an allocation failure). The timer is started when the user crosses
 * their soft limit, it is reset when they go below their soft limit.
 */
#define MAX_IQ_TIME  604800	/* (7*24*60*60) 1 week */
#define MAX_DQ_TIME  604800	/* (7*24*60*60) 1 week */

struct quota_id {
	struct rb_node	node;
	qid_t		id;
};

static int mem_check_quota_file(struct super_block *sb, int type)
{
	/* There is no real quota file, nothing to do */
	return 1;
}

/*
 * There is no real quota file. Just allocate rb_root for quota ids and
 * set limits
 */
static int mem_read_file_info(struct super_block *sb, int type)
{
	struct quota_info *dqopt = sb_dqopt(sb);
	struct mem_dqinfo *info = &dqopt->info[type];
	int ret = 0;

	down_read(&dqopt->dqio_sem);
	if (info->dqi_fmt_id != QFMT_MEM_ONLY) {
		ret = -EINVAL;
		goto out_unlock;
	}

	info->dqi_priv = kzalloc(sizeof(struct rb_root), GFP_NOFS);
	if (!info->dqi_priv) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * Used space is stored as unsigned 64-bit value in bytes but
	 * quota core supports only signed 64-bit values so use that
	 * as a limit
	 */
	info->dqi_max_spc_limit = 0x7fffffffffffffffLL; /* 2^63-1 */
	info->dqi_max_ino_limit = 0x7fffffffffffffffLL;

	info->dqi_bgrace = MAX_DQ_TIME;
	info->dqi_igrace = MAX_IQ_TIME;
	info->dqi_flags = 0;

out_unlock:
	up_read(&dqopt->dqio_sem);
	return ret;
}

static int mem_write_file_info(struct super_block *sb, int type)
{
	/* There is no real quota file, nothing to do */
	return 0;
}

/*
 * Free all the quota_id entries in the rb tree and rb_root.
 */
static int mem_free_file_info(struct super_block *sb, int type)
{
	struct mem_dqinfo *info = &sb_dqopt(sb)->info[type];
	struct rb_root *root = info->dqi_priv;
	struct quota_id *entry;
	struct rb_node *node;

	info->dqi_priv = NULL;
	node = rb_first(root);
	while (node) {
		entry = rb_entry(node, struct quota_id, node);
		node = rb_next(&entry->node);

		rb_erase(&entry->node, root);
		kfree(entry);
	}

	kfree(root);
	return 0;
}

/*
 * There is no real quota file, nothing to read. Just insert the id in
 * the rb tree.
 */
static int mem_read_dquot(struct dquot *dquot)
{
	struct mem_dqinfo *info = sb_dqinfo(dquot->dq_sb, dquot->dq_id.type);
	struct rb_node **n = &((struct rb_root *)info->dqi_priv)->rb_node;
	struct rb_node *parent = NULL, *new_node = NULL;
	struct quota_id *new_entry, *entry;
	qid_t id = from_kqid(&init_user_ns, dquot->dq_id);
	struct quota_info *dqopt = sb_dqopt(dquot->dq_sb);
	int ret = 0;

	down_write(&dqopt->dqio_sem);

	while (*n) {
		parent = *n;
		entry = rb_entry(parent, struct quota_id, node);

		if (id < entry->id)
			n = &(*n)->rb_left;
		else if (id > entry->id)
			n = &(*n)->rb_right;
		else
			goto out_unlock;
	}

	new_entry = kmalloc(sizeof(struct quota_id), GFP_NOFS);
	if (!new_entry) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	new_entry->id = id;
	new_node = &new_entry->node;
	rb_link_node(new_node, parent, n);
	rb_insert_color(new_node, (struct rb_root *)info->dqi_priv);
	dquot->dq_off = 1;
	/*
	 * Make sure dquot is never released by a shrinker because we
	 * rely on quota infrastructure to store mem_dqblk in dquot.
	 */
	set_bit(DQ_NO_SHRINK_B, &dquot->dq_flags);
	set_bit(DQ_FAKE_B, &dquot->dq_flags);

out_unlock:
	up_write(&dqopt->dqio_sem);
	return ret;
}

static int mem_write_dquot(struct dquot *dquot)
{
	/* There is no real quota file, nothing to do */
	return 0;
}

static int mem_release_dquot(struct dquot *dquot)
{
	/*
	 * Everything is in memory only, release once we're done with
	 * quota via mem_free_file_info().
	 */
	return 0;
}

static int mem_get_next_id(struct super_block *sb, struct kqid *qid)
{
	struct mem_dqinfo *info = sb_dqinfo(sb, qid->type);
	struct rb_node *node = ((struct rb_root *)info->dqi_priv)->rb_node;
	qid_t id = from_kqid(&init_user_ns, *qid);
	struct quota_info *dqopt = sb_dqopt(sb);
	struct quota_id *entry = NULL;
	int ret = 0;

	down_read(&dqopt->dqio_sem);
	while (node) {
		entry = rb_entry(node, struct quota_id, node);

		if (id < entry->id)
			node = node->rb_left;
		else if (id > entry->id)
			node = node->rb_right;
		else
			goto got_next_id;
	}

	if (!entry) {
		ret = -ENOENT;
		goto out_unlock;
	}

	if (id > entry->id) {
		node = rb_next(&entry->node);
		if (!node) {
			ret = -ENOENT;
			goto out_unlock;
		}
		entry = rb_entry(node, struct quota_id, node);
	}

got_next_id:
	*qid = make_kqid(&init_user_ns, qid->type, entry->id);
out_unlock:
	up_read(&dqopt->dqio_sem);
	return ret;
}

static const struct quota_format_ops mem_format_ops = {
	.check_quota_file	= mem_check_quota_file,
	.read_file_info		= mem_read_file_info,
	.write_file_info	= mem_write_file_info,
	.free_file_info		= mem_free_file_info,
	.read_dqblk		= mem_read_dquot,
	.commit_dqblk		= mem_write_dquot,
	.release_dqblk		= mem_release_dquot,
	.get_next_id		= mem_get_next_id,
};

static struct quota_format_type mem_quota_format = {
	.qf_fmt_id	= QFMT_MEM_ONLY,
	.qf_ops		= &mem_format_ops,
	.qf_owner	= THIS_MODULE
};

static int __init init_mem_quota_format(void)
{
	return register_quota_format(&mem_quota_format);
}

static void __exit exit_mem_quota_format(void)
{
	unregister_quota_format(&mem_quota_format);
}

module_init(init_mem_quota_format);
module_exit(exit_mem_quota_format);
