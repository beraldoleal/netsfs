/*
 *  netsfs - Network Stats File System
 *          
 *  A virtual file system to show network statics to sysadmins.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License version
 *  2 as published by the Free Software Foundation.
 * 
 *  Copyright 2009 Beraldo Leal <beraldo at beraldoleal.com>
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

#define NETSFS_MAGIC 0x19980122
#define TMPSIZE 20
#define NCOUNTERS 1

static atomic_t counters[NCOUNTERS];
static atomic_t counter, subcounter;

static struct super_operations netsfs_s_ops = {
	.statfs			= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

static inline unsigned int blksize_bits(unsigned int size)
{
	unsigned int bits = 8;
	do {
		bits++;
		size >>= 1;
	} while (size > 256);
 
	return bits;
}

/*
 * Anytime we make a file or directory in our filesystem we need to
 * come up with an inode to represent it internally.  This is
 * the function that does that job.  All that's really interesting
 * is the "mode" parameter, which says whether this is a directory
 * or file, and gives the permissions.
 */
static struct inode *netsfs_make_inode(struct super_block *sb, int mode)
{
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_mode = mode;
		ret->i_uid = ret->i_gid = 0;
		ret->i_blkbits = blksize_bits(PAGE_CACHE_SIZE);
		ret->i_blocks = 0;
		ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
	}
	return ret;
}

static int netsfs_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;

/*	if (inode->i_ino > NCOUNTERS)
		return -ENODEV;
	filp->private_data = counters + inode->i_ino - 1;*/
	return 0;
}

#define TMPSIZE 20
/*
 * Read a file.  Here we increment and read the counter, then pass it
 * back to the caller.  The increment only happens if the read is done
 * at the beginning of the file (offset = 0); otherwise we end up counting
 * by twos.
 */
static ssize_t netsfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	atomic_t *counter = (atomic_t *) filp->private_data;
	int v, len;
	char tmp[TMPSIZE];
/*
 * Encode the value, and figure out how much of it we can pass back.
 */
	v = atomic_read(counter);
	if (*offset > 0)
		v -= 1;  /* the value returned when offset was zero */
	else
		atomic_inc(counter);
	len = snprintf(tmp, TMPSIZE, "%d\n", v);
	if (*offset > len)
		return 0;
	if (count > len - *offset)
		count = len - *offset;
/*
 * Copy it back, increment the offset, and we're done.
 */
	if (copy_to_user(buf, tmp + *offset, count))
		return -EFAULT;
	*offset += count;
	return count;
}

/*
 * Write a file.
 */
static ssize_t netsfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	atomic_t *counter = (atomic_t *) filp->private_data;
	char tmp[TMPSIZE];
/*
 * Only write from the beginning.
 */
	if (*offset != 0)
		return -EINVAL;
/*
 * Read the value from the user.
 */
	if (count >= TMPSIZE)
		return -EINVAL;
	memset(tmp, 0, TMPSIZE);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
/*
 * Store it in the counter and we are done.
 */
	atomic_set(counter, simple_strtol(tmp, NULL, 10));
	return count;
}

static struct file_operations netsfs_file_ops = {
  .open = netsfs_open,
  .read   = netsfs_read_file,
  .write  = netsfs_write_file,
};

/*
struct tree_descr OurFiles[] = {
  { NULL, NULL, 0 },
  { .name = "counter",
    .ops = &netsfs_file_ops,
    .mode = S_IWUSR|S_IRUGO },
  { "", NULL, 0 }
};
*/

/*
 * Create a file mapping a name to a counter.
 */
static struct dentry *netsfs_create_file (struct super_block *sb,
		struct dentry *dir, const char *name,
		atomic_t *counter)
{
	struct dentry *dentry = NULL;
	struct inode *inode;
	struct qstr qname;
/*
 * Make a hashed version of the name to go with the dentry.
 */
	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);
/*
 * Now we can create our dentry and the inode to go with it.
 */
	dentry = d_alloc(dir, &qname);
	if (! dentry)
		goto out;
	inode = netsfs_make_inode(sb, S_IFREG | 0644);
	if (! inode)
		goto out_dput;
	inode->i_fop = &netsfs_file_ops;
	inode->i_private = counter;
/*
 * Put it all into the dentry cache and we're done.
 */
	d_add(dentry, inode);
	return dentry;
	return 0;
/*
 * Then again, maybe it didn't work.
 */
  out_dput:
	dput(dentry);
  out:
	return 0;
}

/*
 * Create a directory which can be used to hold files.  This code is
 * almost identical to the "create file" logic, except that we create
 * the inode with a different mode, and use the libfs "simple" operations.
 */
static struct dentry *netsfs_create_dir (struct super_block *sb,
		struct dentry *parent, const char *name)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);
	dentry = d_alloc(parent, &qname);
	if (! dentry)
		goto out;

	inode = netsfs_make_inode(sb, S_IFDIR | 0644);
	if (! inode)
		goto out_dput;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;

	d_add(dentry, inode);
	return dentry;

  out_dput:
		dput(dentry);
  out:
		return 0;
}

static void netsfs_create_files (struct super_block *sb, struct dentry *root)
{
	struct dentry *subdir;
/*
 * One counter in the top-level directory.
 */
	atomic_set(&counter, 0);
	netsfs_create_file(sb, root, "counter", &counter);
/*
 * And one in a subdirectory.
 */
	atomic_set(&subcounter, 0);
	subdir = netsfs_create_dir(sb, root, "subdir");
	if (subdir)
		netsfs_create_file(sb, subdir, "subcounter", &subcounter);
}

static int netsfs_fill_super (struct super_block *sb, void *data, int silent)
{
	struct inode *root;
	struct dentry *root_dentry;

	// Basic parameters.
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = NETSFS_MAGIC;
	sb->s_op = &netsfs_s_ops;

/*
 * We need to conjure up an inode to represent the root directory
 * of this filesystem.  Its operations all come from libfs, so we
 * don't have to mess with actually *doing* things inside this
 * directory.
 */
	root = netsfs_make_inode (sb, S_IFDIR | 0755);
	if (! root)
		goto out;
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;
/*
 * Get a dentry to represent the directory in core.
 */
	root_dentry = d_alloc_root(root);
	if (! root_dentry)
		goto out_iput;
	sb->s_root = root_dentry;

	netsfs_create_files (sb, root_dentry);
	return 0;
	
  out_iput:
		iput(root);
  out:
		return -ENOMEM;
//	return simple_fill_super(sb, NETSFS_MAGIC, OurFiles);

}

static int netsfs_get_super(struct file_system_type *fst,
 int flags, const char *devname, void *data,
 struct vfsmount *mnt)
{
	return get_sb_single(fst, flags, data, netsfs_fill_super, mnt);
}

static struct file_system_type netsfs_type = {
  .owner    = THIS_MODULE,
  .name     = "netsfs",
  .get_sb   = netsfs_get_super,
  .kill_sb  = kill_litter_super
};


static int __init netsfs_init(void)
{
	int i;

	printk("Kernel now with netsfs support.\n");
	for (i = 0; i < NCOUNTERS; i++)
		atomic_set(counters + i, 0);
	return register_filesystem(&netsfs_type);
}

static void __exit netsfs_exit(void)
{
	printk("Kernel now without netsfs support.\n");
	unregister_filesystem(&netsfs_type);
}

module_init(netsfs_init);
module_exit(netsfs_exit);

