/*
 *  netsfs.h - part of netsfs, a tiny little debug file system for network packets analysis.
 *
 *  Copyright (C) 2012 Beraldo Leal <beraldo@ime.usp.br>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License version
 *      2 as published by the Free Software Foundation.
 *
 */

#define NETSFS_MAGIC 0x19980122

static ssize_t netsfs_read_file(struct file *filp, char *buf, size_t length, loff_t *offset);

struct netsfs_mount_opts {
        uid_t uid;
        gid_t gid;
        umode_t mode;
};

enum {
        Opt_uid,
        Opt_gid,
        Opt_mode,
        Opt_err
};

static struct super_operations netsfs_ops = {
        .statfs         = simple_statfs,
        .drop_inode     = generic_delete_inode,
};

struct netsfs_fs_info {
        struct netsfs_mount_opts mount_opts;
};

static struct file_operations netsfs_file_ops = {
  .read   = netsfs_read_file,
};
