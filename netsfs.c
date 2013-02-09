/*
 *  inode.c - part of netsfs, a tiny little debug file system for network packets analysis.
 *
 *  Copyright (C) 2012 Beraldo Leal <beraldo@ime.usp.br>
 *
 *  This use the same functions used in debugfs by Greg Kroah-Hartman and ramfs by Linus Torvalds.
 *  I dont know if is possible create a fs using debugfs outside debugfs mount point. If possible,
 *  should us rewrite using debugfs?
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License version
 *      2 as published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/if_ether.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "netsfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

struct dentry *root = NULL;
struct packet_type netsfs_pseudo_proto;

static struct inode *netsfs_get_inode(struct super_block *sb, const struct inode *dir, int mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);

    if (inode) {
        inode->i_ino = get_next_ino();
        inode->i_mode = mode;
        inode->i_uid = inode->i_gid = 0;
        inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
        switch (mode & S_IFMT) {
        default:
            init_special_inode(inode, mode, dev);
            break;
        case S_IFREG:
            inode->i_fop = &netsfs_file_ops;
            break;
        case S_IFDIR:
            inode->i_op = &simple_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;
            /* directory inodes start off with i_nlink == 2
             * (for "." entry) */
            inc_nlink(inode);
            break;
        case S_IFLNK:
            inode->i_op = &page_symlink_inode_operations;
            break;
        }
    }
    return inode;
}


static int netsfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    struct inode * inode = netsfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);   /* Extra count - pin the dentry in core */
        error = 0;
        dir->i_mtime = dir->i_ctime = CURRENT_TIME;
    }
    return error;
}

static int netsfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
    int retval = netsfs_mknod(dir, dentry, mode | S_IFDIR, 0);
    if (!retval)
        inc_nlink(dir);
    return retval;
}

static int netsfs_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
    return netsfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int netsfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
    struct inode *inode;
    int error = -ENOSPC;

    inode = netsfs_get_inode(dir->i_sb, dir, S_IFLNK|S_IRWXUGO, 0);
    if (inode) {
        int l = strlen(symname)+1;
        error = page_symlink(inode, symname, l);
        if (!error) {
            d_instantiate(dentry, inode);
            dget(dentry);
            dir->i_mtime = dir->i_ctime = CURRENT_TIME;
        } else
            iput(inode);
    }
    return error;
}

static int netsfs_create_by_name(const char *name, mode_t mode, struct dentry *parent,
    struct dentry **dentry, void *data)
{
    int error =0;

    if (!parent)
        parent = root;

    *dentry = NULL;
    mutex_lock(&parent->d_inode->i_mutex);
    *dentry = lookup_one_len(name, parent, strlen(name));
    if (!IS_ERR(*dentry)) {
        switch (mode & S_IFMT) {
        case S_IFDIR:
            error = netsfs_mkdir(parent->d_inode, *dentry, mode);
            break;
//        case S_IFLNK:
//            error = netsfs_link(parent->d_inode, *dentry, target);
//            break;
        default:
            error = netsfs_create(parent->d_inode, *dentry, mode, data);
            break;
        }
        dput(*dentry);
    } else
        error = PTR_ERR(*dentry);

    mutex_unlock(&parent->d_inode->i_mutex);
    return error;
}

int netsfs_packet_handler(struct sk_buff *skb,
                          struct net_device *dev,
                          struct packet_type *pkt,
                          struct net_device *dev2)
{

    int len, err;

    len = skb->len;
    if (len > ETH_DATA_LEN) {
        printk(KERN_INFO "%s:len > ETH_DATA_LEN!\n", THIS_MODULE->name);
        err = -ENOMEM;
        goto fail;
    }

    /* check for ip header, in this case never will get nothing different of ETH_P_IP, but this switch
     * is here just in case you change netsfs_pseudo_proto.type
     */
    switch (ntohs(pkt->type))
    {
    case ETH_P_RARP:
    case ETH_P_ARP:
        printk(KERN_INFO "%s: ARP/RARP Packet\n", THIS_MODULE->name);
        break;
    case ETH_P_IP:
        printk(KERN_INFO "%s: IPv4 (0x%.4X) Packet\n", THIS_MODULE->name, ntohs(pkt->type));
        break;
    default:
        printk(KERN_INFO "%s: Unknow packet (0x%.4X)\n", THIS_MODULE->name, ntohs(pkt->type));
        break;
    }

    /* We need free the skb, this is a copy! */
    dev_kfree_skb(skb);

    return 0;
fail:
    dev_kfree_skb(skb);
    return err;
}

static ssize_t netsfs_read_file(struct file *filp, char *buf, size_t length, loff_t *offset)
{
    if(*offset > 0)
        return 0;

    if (copy_to_user(buf, "Data here\n", 10))
        return -EFAULT;

    *offset += length; // advance the offset
    return 10;
}

 
static int netsfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct netsfs_fs_info *fsi;
    struct inode *inode = NULL;
    int err;

    save_mount_options(sb, data);

    fsi = kzalloc(sizeof(struct netsfs_fs_info), GFP_KERNEL);
    sb->s_fs_info = fsi;
    if (!fsi) {
        err = -ENOMEM;
        goto fail;
    }

    // Basic parameters.
    sb->s_blocksize = PAGE_CACHE_SIZE;
    sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
    sb->s_magic = NETSFS_MAGIC;
    sb->s_op = &netsfs_ops;


    inode = netsfs_get_inode(sb, NULL, S_IFDIR | 0755, 0);
    if (!inode) {
        err = -ENOMEM;
        goto fail;
    }

    root = d_alloc_root(inode);
    sb->s_root = root;
    if (!root) {
            err = -ENOMEM;
            goto fail;
    }

    /* register protocol handler, for now, only IPv4. */
    netsfs_pseudo_proto.type = htons(ETH_P_IP);
    netsfs_pseudo_proto.dev = NULL;
    netsfs_pseudo_proto.func = netsfs_packet_handler;
    dev_add_pack(&netsfs_pseudo_proto);

    return 0;

fail:
    kfree(fsi);
    sb->s_fs_info = NULL;
    iput(inode);
    return err;
}

static struct dentry *netsfs_mount(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data)
{
    return mount_single(fs_type, flags, data, netsfs_fill_super);
}

static struct file_system_type netsfs_type = {
    .owner    = THIS_MODULE,
    .name     = "netsfs",
    .mount    = netsfs_mount,
    .kill_sb  = kill_litter_super,
};

static int __init netsfs_init(void)
{
    printk("Kernel now with netsfs support.\n");
    return register_filesystem(&netsfs_type);
}

static void __exit netsfs_exit(void)
{
    dev_remove_pack(&netsfs_pseudo_proto);
    unregister_filesystem(&netsfs_type);
    printk("Kernel now without netsfs support.\n");
}

module_init(netsfs_init);
module_exit(netsfs_exit);
