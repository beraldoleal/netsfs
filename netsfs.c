/*
 *  netsfs - Network Stats File System
 *          
 *  A virtual file system to show network statistics to sysadmins.
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

static ssize_t netsfs_read_file(struct file *filp, char *buf,
		size_t length, loff_t *offset)
{
   int i;
   if(*offset > 0)
       return 0;

    if ( copy_to_user(buf, "Data here\n", 10))
			return -EFAULT;

    //           copy_to_user(buf, file_buf, buflen);
    *offset += length; // advance the offset
    return 10;


/*  int bytes_read = 0;
  static char *Message_Ptr;
  char line[10];

	sprintf(line, "Hello\n");

  Message_Ptr = line;
  if (*Message_Ptr == 0)
    return 0;

  while (length && *Message_Ptr)  {
    put_user(*(Message_Ptr++), buf++);
    length --;
    bytes_read ++;
  }

  return bytes_read; */

}

/*	atomic_t *counter = (atomic_t *) filp->private_data;
	int v, len;
	char tmp[TMPSIZE];
*
 * Encode the value, and figure out how much of it we can pass back.
 *
	v = atomic_read(counter);
	if (*offset > 0)
		v -= 1;  * the value returned when offset was zero *
	else
		atomic_inc(counter);
	len = snprintf(tmp, TMPSIZE, "%d\n", v);
	if (*offset > len)
		return 0;
	if (count > len - *offset)
		count = len - *offset;
*
 * Copy it back, increment the offset, and we're done.
 *
	if (copy_to_user(buf, tmp + *offset, count))
		return -EFAULT;
	*offset += count;
	return count;
}
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
//  .open = netsfs_open,
  .read   = netsfs_read_file,
//  .write  = netsfs_write_file,
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

static struct dentry *netsfs_create_file (struct super_block *sb,
		struct dentry *parent, const char *name, atomic_t *counter)
{
	struct dentry *dentry = NULL;
	struct inode *inode;
	struct qstr qname;

	printk("Tentando criar %s\n", name);
	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(qname.name, qname.len);

  dentry = d_lookup(parent, &qname);

	if (!dentry) {
		dentry = d_alloc(parent, &qname);
		if (dentry) {
			inode = netsfs_make_inode(sb, S_IFREG | 0644);
			if (!inode) {
				dput(dentry);
				return -ENOMEM;
			} else {
				inode->i_fop = &netsfs_file_ops;
				inode->i_private = counter;
				d_add(dentry, inode);
			}
		} else 
			return -ENOMEM;
	}else
		dput(dentry);

	return dentry;
}

static struct dentry *netsfs_create_dir (struct super_block *sb,
		struct dentry *parent, const char *name)
{
	struct dentry *dentry = NULL;
	struct inode *inode;
	struct qstr qname;

	printk("Tentando criar %s\n", name);
	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(qname.name, qname.len);
	
	dentry = d_lookup(parent, &qname);

	if (!dentry) {
		dentry = d_alloc(parent, &qname);
		if (dentry) {
			inode = netsfs_make_inode(sb, S_IFDIR | 0755);
			if (!inode) {
				dput(dentry);
				return -ENOMEM;
			} else {
				inode->i_op = &simple_dir_inode_operations;
				inode->i_fop = &simple_dir_operations;
				d_add(dentry, inode);
			}
		} else 
			return -ENOMEM;
	} else	
		dput(dentry);
		
	return dentry;
}

static void netsfs_create_files (struct super_block *sb, struct dentry *root)
{
	struct dentry *subdir;
	
	atomic_set(&counter, 0);
	netsfs_create_file(sb, root, "counter", &counter);

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

	root = netsfs_make_inode (sb, S_IFDIR | 0755);
	if (! root)
		goto out;
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;
	
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

