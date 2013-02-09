/*
 *  inode.c - part of netsfs, a tiny little debug file system for network packets analysis.
 *
 *  Copyright (C) 2012 Beraldo Leal <beraldo@ime.usp.br>
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
#include <linux/pagemap.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include "netsfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

static ssize_t netsfs_read_file(struct file *filp, char *buf,
                size_t length, loff_t *offset)
{
    if(*offset > 0)
        return 0;

    if (copy_to_user(buf, "Data here\n", 10))
        return -EFAULT;

    *offset += length; // advance the offset
    return 10;
}

static struct inode *netsfs_make_inode(struct super_block *sb, const struct inode *dir, int mode, dev_t dev)
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
        }
    }
    return inode;
}
 
static int netsfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct netsfs_fs_info *fsi;
    struct inode *inode = NULL;
    struct dentry *root;
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


    inode = netsfs_make_inode(sb, NULL, S_IFDIR | 0755, 0);
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

    //netsfs_create_files();
    return 0;

fail:
    kfree(fsi);
    sb->s_fs_info = NULL;
    iput(inode);
    return err;
}

static struct dentry *netsfs_mount(struct file_system_type *fs_type,
                                   int flags,
                                   const char *dev_name,
                                   void *data)
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
    printk("Kernel now without netsfs support.\n");
    unregister_filesystem(&netsfs_type);
}

module_init(netsfs_init);
module_exit(netsfs_exit);
