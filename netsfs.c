/* vim: tabstop=4:softtabstop=4:shiftwidth=4:expandtab
 * */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/namei.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#define NETSFS_MAGIC 0x8723892
#define NETSFS_DEFAULT_MODE      0755

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Beraldo Leal");

static const struct inode_operations netsfs_file_inode_operations;
static const struct file_operations netsfs_file_operations;

static int netsfs_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd);
static int netsfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname);
static int netsfs_mkdir(struct inode * dir, struct dentry * dentry, int mode);
static int netsfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
static int netsfs_create_by_name(const char *name, mode_t mode,
        struct dentry *parent,
        struct dentry **dentry,
        void *data);


static struct dentry *netsfs_root;

struct packet_type netsfs_pseudo_proto;

static const struct inode_operations netsfs_dir_inode_operations = {
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

static const struct super_operations netsfs_ops = {
    .statfs         = simple_statfs,
    .drop_inode     = generic_delete_inode,
    .show_options   = generic_show_options,
};

struct netsfs_mount_opts {
    umode_t mode;
};

enum {
    Opt_mode,
    Opt_err
};

static const match_table_t tokens = {
    {Opt_mode, "mode=%o"},
    {Opt_err, NULL}
};


struct netsfs_fs_info {
    struct netsfs_mount_opts mount_opts;
};

int netsfs_packet_handler(struct sk_buff *skb,
        struct net_device *dev,
        struct packet_type *pkt,
        struct net_device *dev2)
{

    int len, err;
    //struct dentry *dentry;

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


static int netsfs_parse_options(char *data, struct netsfs_mount_opts *opts)
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

struct inode *netsfs_get_inode(struct super_block *sb,
        const struct inode *dir, int mode, dev_t dev)
{
    struct inode * inode = new_inode(sb);

    if (inode) {
        inode->i_ino = get_next_ino();
        inode_init_owner(inode, dir, mode);
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

static int netsfs_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
    int retval;

    printk("%s:%s:%d - Start. dir->i_ino == %lu, dentry->d_iname == %s\n",
            THIS_MODULE->name,
            __FUNCTION__,
            __LINE__,
            dir->i_ino,
            dentry->d_iname);

    retval = netsfs_mknod(dir, dentry, mode | S_IFDIR, 0);

    if (!retval)
        inc_nlink(dir);

    printk("%s:%s:%d - End. inode->i_ino == %lu, dentry->d_iname == %s\n",
            THIS_MODULE->name,
            __FUNCTION__,
            __LINE__,
            dir->i_ino,
            dentry->d_iname);

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


static int netsfs_create_by_name(const char *name, mode_t mode,
        struct dentry *parent,
        struct dentry **dentry,
        void *data)
{
    struct qstr qname;
    int error = 0;

    printk("%s:%s:%d - Start.\n", THIS_MODULE->name, __FUNCTION__, __LINE__);

    /* If the parent is not specified, we create it in the root.
     * We need the root dentry to do this, which is in the super
     * block. A pointer to that is in the struct vfsmount that we
     * have around.
     */
    if (!parent) {
        printk("%s:%s:%d - parent == NULL, updating with netsfs_root.\n",
                THIS_MODULE->name,
                __FUNCTION__,
                __LINE__);
        parent = netsfs_root;
    }

    printk("%s:%s:%d - parent != NULL. parent->d_inode->i_ino == %lu\n",
            THIS_MODULE->name,
            __FUNCTION__,
            __LINE__,
            parent->d_inode->i_ino);

    *dentry = NULL;


    qname.name = name;
    qname.len = strlen (name);
    qname.hash = full_name_hash(qname.name, qname.len);

    printk("%s:%s:%d - Searching for %s (%d) (%u)\n",
            THIS_MODULE->name,
            __FUNCTION__,
            __LINE__,
            qname.name,
            qname.len,
            qname.hash);

    *dentry = d_lookup(parent, &qname);

    if (!*dentry) {
        printk("%s:%s:%d - Not found.\n",
                THIS_MODULE->name,
                __FUNCTION__,
                __LINE__);

        mutex_lock(&parent->d_inode->i_mutex);
        *dentry = lookup_one_len(name, parent, strlen(name));


        if (!IS_ERR(*dentry)) {
            switch (mode & S_IFMT) {
                case S_IFDIR:
                    error = netsfs_mkdir(parent->d_inode, *dentry, mode);
                    break;
                case S_IFLNK:
                    //        error = netsfs_symlink(parent->d_inode, *dentry, mode, data);
                    //        break;
                default:
                    error = netsfs_create(parent->d_inode, *dentry, mode, data);
                    break;
            }
            dput(*dentry);
        } else
            error = PTR_ERR(*dentry);

        mutex_unlock(&parent->d_inode->i_mutex);
    }
    printk("%s:%s:%d - End.\n", THIS_MODULE->name, __FUNCTION__, __LINE__);

    return error;

fail:
    *dentry = NULL;
    return error;
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

    root = d_alloc_root(inode);
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

static void netsfs_register_pack(void)
{
    netsfs_pseudo_proto.type = htons(ETH_P_IP);
    netsfs_pseudo_proto.dev = NULL;
    netsfs_pseudo_proto.func = netsfs_packet_handler;
    dev_add_pack(&netsfs_pseudo_proto);
}


struct dentry *netsfs_mount(struct file_system_type *fs_type,
        int flags, const char *dev_name, void *data)
{
    struct dentry *root;
    struct dentry *dentry;
    struct dentry *dentry2;

    printk("%s:%s:%d - Start.\n", THIS_MODULE->name, __FUNCTION__, __LINE__);
    root = mount_nodev(fs_type, flags, data, netsfs_fill_super);
    if (IS_ERR(root))
        goto out;

    netsfs_root = root;
    netsfs_register_pack();

    printk("%s:%s:%d - End.\n", THIS_MODULE->name, __FUNCTION__, __LINE__);

    printk("%s:%s:%d - netsfs_root->d_inode->i_ino == %lu\n",
            THIS_MODULE->name,
            __FUNCTION__,
            __LINE__,
            netsfs_root->d_inode->i_ino);

    // Try to create two dirs with the same name
    netsfs_create_by_name("ipv4", S_IFDIR, NULL, &dentry, NULL);
    netsfs_create_by_name("ipv4", S_IFDIR, NULL, &dentry2, NULL);

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
    //struct dentry *dentry;

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
