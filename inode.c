/*
 * inode.c - part of netsfs, a tiny little debug network packets file system
 *
 * Copyright (C) 2012 Beraldo Leal <beraldo@ime.usp.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * vim: tabstop=4:softtabstop=4:shiftwidth=4:expandtab
 *
 */

#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/namei.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/kfifo.h>
#include <linux/printk.h>
#include <linux/netdevice.h>

#include "internal.h"
#include "proto.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

#define STREAM_BUF_LEN 2000

#define MAXWRITEBUF 10

static struct packet_type netsfs_pseudo_proto;
static const struct inode_operations netsfs_file_inode_operations;

struct dentry *netsfs_root;

unsigned int debug_level = 0;

struct dentry *get_root(void)
{
    return netsfs_root;
}

/* change from linux/lib/hexdump.c */
void netsfs_hex_dump(char *to, const char *prefix_str, int prefix_type,
                     int rowsize, int groupsize, const void *buf,
                     size_t len, bool ascii)
{
    const u8 *ptr = buf;
    int i, linelen, remaining = len;
    unsigned char linebuf[32 * 3 + 2 + 32 + 1];

    if (rowsize != 16 && rowsize != 32)
        rowsize = 16;

    for (i = 0; i < len; i += rowsize) {
        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
                   linebuf, sizeof(linebuf), ascii);

        switch (prefix_type) {
        case DUMP_PREFIX_ADDRESS:
            to += sprintf(to, "%s%p: %s\n",  prefix_str, ptr + i, linebuf);
            break;
        case DUMP_PREFIX_OFFSET:
            to += sprintf(to, "%s%.8x: %s\n", prefix_str, i, linebuf);
            break;
        default:
            to += sprintf(to, "%s%s\n", prefix_str, linebuf);
            break;
        }
    }
}

void netsfs_hex_dump_bytes(char *to, const char *prefix_str, int prefix_type,
                           const void *buf, size_t len)
{
    netsfs_hex_dump(to, prefix_str, prefix_type, 16, 1,
                    buf, len, true);
}

static unsigned int get_debug_level(char* buffer)
{
    int level;
    if (sscanf(buffer, "%d", &level))
        return level;
    else
        return -EFAULT;
}

static ssize_t netsfs_file_write(struct file *file, const char __user * buf,
                                 size_t len, loff_t *ppos)
{
    int level;
    char write_buff[MAXWRITEBUF];

    if (len > MAXWRITEBUF)
        return -EFAULT;

    if (copy_from_user(write_buff, buf, len))
        return -EFAULT;
    else {
        level = get_debug_level(write_buff);
        if (level >= 0)
            debug_level = level;
        else
            return -EFAULT;
    }
    *ppos += len;
    return len;
}

/* User space ask to read the "stats" file. */
static ssize_t netsfs_read_stats(struct file *file, char __user *buf,
                                 size_t count, loff_t *ppos)
{
    struct netsfs_dir_private *d_private;
    char *stats_buf;
    size_t ret = 0;

    if (*ppos != 0)
        return 0;

    stats_buf = kmalloc(512 * sizeof(char), GFP_KERNEL);
    d_private = file->f_dentry->d_parent->d_inode->i_private;

    ret = snprintf(stats_buf, STREAM_BUF_LEN, "bytes: %lld\ncount: %lld\n",
                  d_private->bytes, d_private->count);

    if (ret > 0)
        ret = simple_read_from_buffer(buf, count, ppos, stats_buf, ret);

    if (stats_buf) kfree(stats_buf);
    return ret;
}


/* User space ask to read the "stream" file. */
static ssize_t netsfs_read_stream(struct file *file, char __user *buf,
                                  size_t count, loff_t *ppos)
{
    struct netsfs_dir_private *d_private;
    struct sk_buff *skb;

    char *stream_buf = NULL;
    char *raw_buf = NULL;

    char *mac_string, *network_string, *transport_string;
    size_t ret = 0;

    if (*ppos != 0)
        return 0;

    spin_lock(&file->f_dentry->d_parent->d_inode->i_lock);
    d_private = file->f_dentry->d_parent->d_inode->i_private;
    skb = cq_get(&d_private->queue_skbuff);
    spin_unlock(&file->f_dentry->d_parent->d_inode->i_lock);
    if (skb) {
        mac_string = kmalloc(sizeof(char)*80, GFP_KERNEL);
        network_string = kmalloc(sizeof(char)*80, GFP_KERNEL);
        transport_string = kmalloc(sizeof(char)*80, GFP_KERNEL);

        get_mac_string(mac_string, skb);
        get_network_string(network_string, skb);
        get_transport_string(transport_string, skb);

        stream_buf = kmalloc(10048 * sizeof(char), GFP_KERNEL);

        if (debug_level > 0) {
            raw_buf = kmalloc(5024 * sizeof(char), GFP_KERNEL);
            netsfs_hex_dump_bytes(raw_buf, "", -1, skb->data, skb->len);

            ret = sprintf(stream_buf, "%s\n%s\n%s\n%s", mac_string,
                                                      network_string,
                                                      transport_string,
                                                      raw_buf);
        }else
            ret = sprintf(stream_buf, "%s\n%s\n%s\n", mac_string,
                                                      network_string,
                                                      transport_string);


        if (ret > 0)
            ret = simple_read_from_buffer(buf, count, ppos, stream_buf, ret);

        dev_kfree_skb(skb);
        if (mac_string) kfree(mac_string);
        if (network_string) kfree(network_string);
        if (transport_string) kfree(transport_string);
        if (stream_buf) kfree(stream_buf);
        if (raw_buf) kfree(raw_buf);
    }
    return ret;
}

/* User space ask to read a read a file */
static ssize_t netsfs_file_read(struct file *file, char __user *buf,
                                size_t count, loff_t *ppos)
{
    struct netsfs_file_private *f_private;

    f_private = file->f_dentry->d_inode->i_private;

    switch(f_private->type) {
        case NETSFS_STATS:
            return netsfs_read_stats(file, buf, count, ppos);
            break;
        case NETSFS_STREAM:
            return netsfs_read_stream(file, buf, count, ppos);
            break;
        default:
            break;
    }
    return 0;
}

/* Comment options here to disable operations to user */
const struct inode_operations netsfs_dir_inode_operations = {
    .create         = netsfs_create,
    .lookup         = simple_lookup,
    .link           = simple_link,
    .unlink         = simple_unlink,
    .symlink        = netsfs_symlink,
    .mkdir          = netsfs_mkdir,
    .rmdir          = simple_rmdir,
    .mknod          = netsfs_mknod,
    .rename         = simple_rename,
};

struct super_operations netsfs_ops = {
    .statfs         = simple_statfs,
    .drop_inode     = generic_delete_inode,
    .show_options   = generic_show_options,
};

static const struct file_operations netsfs_file_operations = {
    .read           = netsfs_file_read,
    .write          = netsfs_file_write,
};

const match_table_t tokens = {
    {Opt_mode, "mode=%o"},
    {Opt_err, NULL}
};


extern void netsfs_inc_inode_size(struct inode *inode, loff_t inc)
{
    loff_t oldsize, newsize;
    struct netsfs_dir_private *d_private;

    if(inode == NULL)
        inode = netsfs_root->d_inode;

    //printk(KERN_INFO "%s: Updating inode %lu size to %lld\n",
    //        THIS_MODULE->name,
    //        inode->i_ino,
    //        inc);

    spin_lock(&inode->i_lock);
    oldsize = i_size_read(inode);
    newsize = oldsize + inc;
    i_size_write(inode, newsize);

    if (inode->i_private == NULL) {
        d_private = kmalloc(sizeof(struct netsfs_dir_private), GFP_KERNEL);
        cq_new(&d_private->queue_skbuff, FIFO_SIZE);
        d_private->bytes = newsize;
        d_private->count = 1;
        inode->i_private = d_private; // LOCK HERE
    }else{
        ((struct netsfs_dir_private *) inode->i_private)->bytes = newsize;
        ((struct netsfs_dir_private *) inode->i_private)->count += 1;
    }
    spin_unlock(&inode->i_lock);
}


struct inode *netsfs_get_inode(struct super_block *sb,
        const struct inode *dir, int mode, dev_t dev)
{
    struct inode * inode = new_inode(sb);

    if (inode) {
        inode->i_ino = get_next_ino();
        inode->i_mode = mode;
        inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
        switch (mode & S_IFMT) {
            default:
                init_special_inode(inode, mode, dev);
                break;
            case S_IFREG:
                inode->i_op = &netsfs_file_inode_operations;
                inode->i_fop = &netsfs_file_operations;
                break;
            case S_IFDIR:
                inode->i_op = &netsfs_dir_inode_operations;
                inode->i_fop = &simple_dir_operations;

                /* directory inodes start off with i_nlink == 2 (for "." entry) */
                inc_nlink(inode);
                break;
            case S_IFLNK:
                inode->i_op = &page_symlink_inode_operations;
                break;
        }
    }
    return inode;
}


/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
extern int netsfs_mknod(struct inode *dir, struct dentry *dentry, int mode,
                        dev_t dev)
{
    struct inode *inode;
    int error = -ENOSPC;

    if (dentry->d_inode) {
        //printk("%s:%s:%d - dentry->d_inode != NULL, aborting.\n",
        //        THIS_MODULE->name,
        //        __FUNCTION__,
        //        __LINE__);
        return -EEXIST;
    }

    inode  = netsfs_get_inode(dir->i_sb, dir, mode, dev);
    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);   /* Extra count - pin the dentry in core */
        error = 0;
        dir->i_mtime = dir->i_ctime = CURRENT_TIME;
    }
    return error;
}

extern int netsfs_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
    int retval;

    //printk("%s:%s:%d - Start. dir->i_ino == %lu, dentry->d_iname == %s\n",
    //        THIS_MODULE->name,
    //        __FUNCTION__,
    //        __LINE__,
    //        dir->i_ino,
    //        dentry->d_iname);

    retval = netsfs_mknod(dir, dentry, mode | S_IFDIR, 0);

    if (!retval) {
        inc_nlink(dir);
        // printk("Alloc fifo for %s\n", dentry->d_iname);
        //printk("%s:%s:%d - End. inode->i_ino == %lu, dentry->d_iname == %s\n",
        //        THIS_MODULE->name,
        //        __FUNCTION__,
        //        __LINE__,
        //        dir->i_ino,
        //        dentry->d_iname);
    }

    return retval;
}

extern int netsfs_create(struct inode *dir, struct dentry *dentry, int mode,
                         struct nameidata *nd)
{
    return netsfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

extern int netsfs_parse_options(char *data, struct netsfs_mount_opts *opts)
{
    substring_t args[MAX_OPT_ARGS];
    int option;
    int token;
    char *p;

    opts->mode = NETSFS_DEFAULT_MODE;

    while ((p = strsep(&data, ",")) != NULL) {
        if (!*p)
            continue;

        token = match_token(p, tokens, args);
        switch (token) {
            case Opt_mode:
                if (match_octal(&args[0], &option))
                    return -EINVAL;
                opts->mode = option & S_IALLUGO;
                break;
                /*
                 * We might like to report bad mount options here;
                 * but traditionally netsfs has ignored all mount options,
                 * and as it is used as a !CONFIG_SHMEM simple substitute
                 * for tmpfs, better continue to ignore other mount options.
                 */
        }
    }
    return 0;
}


extern int netsfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
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


extern int netsfs_create_by_name(const char *name, mode_t mode, struct dentry *parent,
                                 struct dentry **dentry, void *data, netsfs_file_type_t type)
{
    int error = 0;

    //printk("%s:%s:%d - Start.\n",
    //        THIS_MODULE->name,
    //        __FUNCTION__,
    //        __LINE__);

    /* If the parent is not specified, we create it in the root.
     * We need the root dentry to do this, which is in the super
     * block. A pointer to that is in the struct vfsmount that we
     * have around.
     */
    if (!parent)
        parent = netsfs_root;

    *dentry = NULL;

    mutex_lock(&parent->d_inode->i_mutex);
    *dentry = lookup_one_len(name, parent, strlen(name));
    if (!IS_ERR(*dentry)) {
        switch (mode & S_IFMT) {
            case S_IFDIR:
                //printk("%s:%s:%d - Is a dir, creating...\n",
                //        THIS_MODULE->name,
                //        __FUNCTION__,
                //        __LINE__);
                error = netsfs_mkdir(parent->d_inode, *dentry, mode);
                break;
            case S_IFLNK:
                //        error = netsfs_symlink(parent->d_inode, *dentry, mode, data);
                //        break;
            default:
                error = netsfs_create(parent->d_inode, *dentry, mode, data);
                if (!error) {
                    if ((*dentry)->d_inode->i_private == NULL) {
                        (*dentry)->d_inode->i_private = kmalloc(sizeof(struct netsfs_file_private), GFP_KERNEL);
                        if (!(*dentry)->d_inode->i_private)
                            return -ENOMEM;
                    }
                    ((struct netsfs_file_private *) (*dentry)->d_inode->i_private)->type = type;
                }

                break;
        }
        dput(*dentry);
    } else
        error = PTR_ERR(*dentry);

    mutex_unlock(&parent->d_inode->i_mutex);
    //printk("%s:%s:%d - End.\n",
    //        THIS_MODULE->name,
    //        __FUNCTION__,
    //        __LINE__);

    return error;
}

/* High-Level function. Use this one.
 * Create stats and stream files in parent dir.
 * If parent is NULL, create on top netsfs_root.
 */
extern void netsfs_create_files(struct dentry *parent)
{
    struct dentry *stats;

    if (!parent)
        parent = netsfs_root;

    netsfs_create_by_name("stats", S_IFREG, parent, &stats, NULL, NETSFS_STATS);
    netsfs_create_by_name("stream", S_IFREG, parent, &stats, NULL, NETSFS_STREAM);
}

/* High-Level function. Use this one.
 * Create protocol directory in parent dir.
 * If parent is NULL, create on top netsfs_root.
 */
extern void netsfs_create_dir(const char *proto_name, struct dentry *parent, struct dentry **dentry)
{
    if (!parent)
        parent = netsfs_root;

    if (!proto_name)
        return;

    netsfs_create_by_name(proto_name, S_IFDIR, parent, dentry, NULL, NETSFS_DIR);
}

int netsfs_fill_super(struct super_block *sb, void *data, int silent)
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

    err = netsfs_parse_options(data, &fsi->mount_opts);
    if (err)
        goto fail;

    sb->s_maxbytes          = MAX_LFS_FILESIZE;
    sb->s_blocksize         = PAGE_CACHE_SIZE;
    sb->s_blocksize_bits    = PAGE_CACHE_SHIFT;
    sb->s_magic             = NETSFS_MAGIC;
    sb->s_op                = &netsfs_ops;
    sb->s_time_gran         = 1;

    inode = netsfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0);
    if (!inode) {
        err = -ENOMEM;
        goto fail;
    }

#ifdef HAVE_D_MAKE_ROOT
    root = d_make_root(inode);
#else
    root = d_alloc_root(inode);
#endif

    sb->s_root = root;
    if (!root) {
        err = -ENOMEM;
        goto fail;
    }

    return 0;
fail:
    kfree(fsi);
    sb->s_fs_info = NULL;
    iput(inode);
    return err;
}

struct dentry *netsfs_mount(struct file_system_type *fs_type,
        int flags, const char *dev_name, void *data)
{
    struct dentry *root;
    struct dentry *debug;

    root = mount_nodev(fs_type, flags, data, netsfs_fill_super);
    if (IS_ERR(root))
        goto out;

    netsfs_root = root;

    printk("netsfs_mount: netsfs_root=%p\n", netsfs_root);

    /* Create stats and stream in root dir */
    netsfs_create_files(NULL);

    netsfs_create_by_name("debug", S_IFREG, netsfs_root, &debug, NULL, NETSFS_DEBUG);

    /* register a packet handler */
    netsfs_pseudo_proto.type = htons(ETH_P_ALL);
    netsfs_pseudo_proto.dev = NULL;
    netsfs_pseudo_proto.func = netsfs_packet_handler;
    dev_add_pack(&netsfs_pseudo_proto);

    // printk("%s:%s:%d - End.\n", THIS_MODULE->name, __FUNCTION__, __LINE__);

    // printk("%s:%s:%d - netsfs_root->d_inode->i_ino == %lu\n",
    //         THIS_MODULE->name,
    //         __FUNCTION__,
    //         __LINE__,
    //        netsfs_root->d_inode->i_ino);

out:
    return root;
}

static void netsfs_kill_sb(struct super_block *sb) {
    dev_remove_pack(&netsfs_pseudo_proto);
    kill_litter_super(sb);
}

static struct file_system_type netsfs_fs_type = {
    .owner    = THIS_MODULE,
    .name     = "netsfs",
    .mount    = netsfs_mount,
    .kill_sb  = netsfs_kill_sb,
};

static int __init netsfs_init(void)
{
    int err;

    printk("Kernel now with netsfs support.\n");
    err = register_filesystem(&netsfs_fs_type);
    if (err)
        return err;


    return err;
}

static void __exit netsfs_exit(void)
{
    printk("Kernel now without netsfs support.\n");
    unregister_filesystem(&netsfs_fs_type);
}

module_init(netsfs_init);
module_exit(netsfs_exit);
