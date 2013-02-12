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

struct inode *netsfs_get_inode(struct super_block *sb,
        const struct inode *dir, int mode, dev_t dev);
extern int netsfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
extern int netsfs_mkdir(struct inode * dir, struct dentry * dentry, int mode);
extern int netsfs_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd);
extern int netsfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname);


extern int netsfs_create_by_name(const char *name, mode_t mode, struct dentry *parent,
                                 struct dentry **dentry, void *data);


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


#endif
