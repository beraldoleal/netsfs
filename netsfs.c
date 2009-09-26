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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

#define NETSFS_MAGIC 0x19980122
#define TMPSIZE 20
#define NCOUNTERS 1

#define NF_IP_PRE_ROUTING	0

static struct dentry *netsfs_create_dir (struct dentry *parent, 
	const char *name);

struct super_block *sb2 = NULL;
struct dentry *root_dentry = NULL;

static atomic_t counter, subcounter;

static struct nf_hook_ops nfhook_ops;

static struct super_operations netsfs_s_ops = {
	.statfs			= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

unsigned int nfhook_netsfs(unsigned int hooknum, struct sk_buff *skb,
  const struct net_device *in, const struct net_device *out,
  int (*okfn)(struct sk_buff *))
{
	struct dentry *subdir;
	char p_ether[5], p_ip[4];

	sprintf(p_ether, "%d", eth_hdr(skb)->h_proto);
	sprintf(p_ip, "%d", ip_hdr(skb)->protocol);
//	printk("0x%04x 0x%02x\n", eth_hdr(skb)->h_proto, ip_hdr(skb)->protocol);	

	subdir = netsfs_create_dir(root_dentry, p_ether);

  netsfs_create_dir(subdir, p_ip);

  return NF_ACCEPT;
}

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

static ssize_t netsfs_read_file(struct file *filp, char *buf,
		size_t length, loff_t *offset)
{
   if(*offset > 0)
       return 0;

    if ( copy_to_user(buf, "Data here\n", 10))
			return -EFAULT;

    *offset += length; // advance the offset
    return 10;
}

static struct file_operations netsfs_file_ops = {
  .read   = netsfs_read_file,
};

static struct dentry *netsfs_create_file (struct dentry *parent, 
	const char *name, atomic_t *counter)
{
	struct dentry *dentry = NULL;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(qname.name, qname.len);

  dentry = d_lookup(parent, &qname);

	if (!dentry) {
		dentry = d_alloc(parent, &qname);
		if (dentry) {
			inode = netsfs_make_inode(sb2, S_IFREG | 0644);
			if (!inode) {
				dput(dentry);
				return (struct dentry *) -ENOMEM;
			} else {
				inode->i_fop = &netsfs_file_ops;
				inode->i_private = counter;
				d_add(dentry, inode);
			}
		} else 
			return (struct dentry *) -ENOMEM;
	}else
		dput(dentry);

	return dentry;
}

static struct dentry *netsfs_create_dir (struct dentry *parent, 
	const char *name)
{
	struct dentry *dentry = NULL;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(qname.name, qname.len);
	
	dentry = d_lookup(parent, &qname);

	if (!dentry) {
		dentry = d_alloc(parent, &qname);
		if (dentry) {
			inode = netsfs_make_inode(sb2, S_IFDIR | 0755);
			if (!inode) {
				dput(dentry);
				return (struct dentry *) -ENOMEM;
			} else {
				inode->i_op = &simple_dir_inode_operations;
				inode->i_fop = &simple_dir_operations;
				d_add(dentry, inode);
			}
		} else 
			return (struct dentry *) -ENOMEM;
	} else	
		dput(dentry);
		
	return dentry;
}

static void netsfs_create_files (void)
{
	struct dentry *subdir;
	
	atomic_set(&counter, 0);
	netsfs_create_file(root_dentry, "counter", &counter);

	atomic_set(&subcounter, 0);
	subdir = netsfs_create_dir(root_dentry, "subdir");
	if (subdir)
		netsfs_create_file(subdir, "subcounter", &subcounter);
}

static int netsfs_fill_super (struct super_block *sb, void *data, int silent)
{
	struct inode *i_root;

	// Basic parameters.
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = NETSFS_MAGIC;
	sb->s_op = &netsfs_s_ops;

	i_root = netsfs_make_inode (sb, S_IFDIR | 0755);
	if (! i_root)
		goto out;
	i_root->i_op = &simple_dir_inode_operations;
	i_root->i_fop = &simple_dir_operations;
	
	root_dentry = d_alloc_root(i_root);
	if (! root_dentry)
		goto out_iput;
	sb->s_root = root_dentry;


	sb2 = (struct super_block*) kmalloc(sizeof(struct super_block), GFP_KERNEL);
	sb2 = sb;

//	netsfs_create_files();
	return 0;
	
  out_iput:
		iput(i_root);
  out:
		return -ENOMEM;
}

static void netsfs_kill_super(struct super_block *sb) {
	nf_unregister_hook(&nfhook_ops);
	kill_litter_super(sb);
}

static int netsfs_get_super(struct file_system_type *fst,
 int flags, const char *devname, void *data,
 struct vfsmount *mnt)
{
	nfhook_ops.hook  = nfhook_netsfs;
	nfhook_ops.hooknum = NF_IP_PRE_ROUTING;
	nfhook_ops.pf  = PF_INET;
	nfhook_ops.priority  = NF_IP_PRI_FIRST;

	nf_register_hook(&nfhook_ops);
	return get_sb_single(fst, flags, data, netsfs_fill_super, mnt);
}

static struct file_system_type netsfs_type = {
  .owner    = THIS_MODULE,
  .name     = "netsfs",
  .get_sb   = netsfs_get_super,
  .kill_sb  = netsfs_kill_super
};

static int __init netsfs_init(void)
{

	printk("Kernel now with netsfs support.\n");
	register_filesystem(&netsfs_type);
	return 0;
}

static void __exit netsfs_exit(void)
{
	printk("Kernel now without netsfs support.\n");
	unregister_filesystem(&netsfs_type);
}

module_init(netsfs_init);
module_exit(netsfs_exit);

