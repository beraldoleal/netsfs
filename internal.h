/* internal.h: netsfs internal definitions
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

#ifndef __NETSFS_INTERNAL_H__
#define __NETSFS_INTERNAL_H__

#include <linux/types.h>
#include <linux/parser.h>
#include <linux/fs.h>

#define NETSFS_MAGIC 0x8723892
#define NETSFS_DEFAULT_MODE      0755

#define STR(x)  #x
typedef enum {
    NETSFS_DIR = 0,
    NETSFS_STATS = 1,
    NETSFS_STREAM = 2
} netsfs_file_type_t;

struct netsfs_file_private {
    netsfs_file_type_t type;
};

struct netsfs_dir_private {
    struct kfifo queue_skbuff;
    u64 count;      // how many frames/packets
    u64 errors;     // how many errors
    loff_t bytes;   // total bytes
};



/* fifo size in elements (struct sk_buff) */
#define FIFO_SIZE 32

/* Declare and INIT kfifo */
static DEFINE_KFIFO(test, struct sk_buff, FIFO_SIZE);

struct inode *netsfs_get_inode(struct super_block *sb,
        const struct inode *dir, int mode, dev_t dev);
extern int netsfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
extern int netsfs_mkdir(struct inode * dir, struct dentry * dentry, int mode);
extern int netsfs_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd);
extern int netsfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname);


extern int netsfs_create_by_name(const char *name, mode_t mode, struct dentry *parent,
                                 struct dentry **dentry, void *data, netsfs_file_type_t type);

extern void netsfs_create_files(struct dentry *parent);
extern void netsfs_create_dir(const char *proto_name, struct dentry *parent, struct dentry **dentry);
extern void netsfs_inc_inode_size(struct inode *inode, loff_t inc);

extern struct dentry *get_root(void);

struct netsfs_mount_opts {
    umode_t mode;
};

enum {
    Opt_mode,
    Opt_err
};


struct netsfs_fs_info {
    struct netsfs_mount_opts mount_opts;
};



/* fifo of pointers */
static inline int cq_new(struct kfifo *fifo, int size)
{
    return kfifo_alloc(fifo, size * sizeof(void *), GFP_KERNEL);
}

static inline void cq_delete(struct kfifo *kfifo)
{
    kfifo_free(kfifo);
}

static inline unsigned int cq_howmany(struct kfifo *kfifo)
{
    return kfifo_len(kfifo) / sizeof(void *);
}

static inline int cq_put(struct kfifo *kfifo, void *p)
{
    return kfifo_in(kfifo, (void *)&p, sizeof(p));
}

static inline int cq_is_full(struct kfifo *kfifo)
{
    if (cq_howmany(kfifo) == FIFO_SIZE)
        return 1;
    else
        return 0;
}

static inline void *cq_get(struct kfifo *kfifo)
{
    unsigned int sz;
    void *p;

    sz = kfifo_out(kfifo, (void *)&p, sizeof(p));
    if (sz != sizeof(p))
        return NULL;

    return p;
}

#endif
