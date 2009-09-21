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
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

#define BNSFS_MAGIC 0x19980122
#define TMPSIZE 20
#define NCOUNTERS 1

static atomic_t counters[NCOUNTERS];

static int netsfs_open(struct inode *inode, struct file *filp)
{
	if (inode->i_ino > NCOUNTERS)
		return -ENODEV;  /* Should never happen.  */
	filp->private_data = counters + inode->i_ino - 1;
	return 0;
}

static ssize_t netsfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	int v, len;
	char tmp[TMPSIZE];
	atomic_t *counter = (atomic_t *) filp->private_data;
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

static ssize_t netsfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	char tmp[TMPSIZE];
	atomic_t *counter = (atomic_t *) filp->private_data;

	if (*offset != 0)
		return -EINVAL;

	if (count >= TMPSIZE)
		return -EINVAL;
	memset(tmp, 0, TMPSIZE);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;

	atomic_set(counter, simple_strtol(tmp, NULL, 10));
	return count;
}

static struct file_operations netsfs_file_ops = {
	.open	= netsfs_open,
	.read 	= netsfs_read_file,
	.write  = netsfs_write_file,
};

struct tree_descr OurFiles[] = {
	{ NULL, NULL, 0 },  /* Skipped */
	{ .name = "counter",
	  .ops = &netsfs_file_ops,
	  .mode = S_IWUSR|S_IRUGO },
	{ "", NULL, 0 }
};

static int netsfs_fill_super (struct super_block *sb, void *data, int silent)
{
	return simple_fill_super(sb, BNSFS_MAGIC, OurFiles);
}

static int netsfs_get_super(struct file_system_type *fst,
 int flags, const char *devname, void *data,
 struct vfsmount *mount)
{
	return get_sb_single(fst, flags, data, netsfs_fill_super, mount);
}

static struct file_system_type netsfs_type = {
	.owner 		= THIS_MODULE,
	.name		= "netsfs",
	.get_sb		= netsfs_get_super,
	.kill_sb	= kill_litter_super,
};


static int __init netsfs_init(void)
{
	int i;

	printk("Kernel now with netsfs support.");
	for (i = 0; i < NCOUNTERS; i++)
		atomic_set(counters + i, 0);
	return register_filesystem(&netsfs_type);
}

static void __exit netsfs_exit(void)
{
	printk("Kernel now without netsfs support.");
	unregister_filesystem(&netsfs_type);
}

module_init(netsfs_init);
module_exit(netsfs_exit);

