/* proto.c: netsfs protocol handler
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

#include <linux/if_ether.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/workqueue.h>
#include <linux/export.h>

#include "proto.h"
#include "internal.h"

struct netsfs_skb_info {
    struct work_struct my_work;
    char mac_name[8];
    char network_name[6];
    int len;
};

/* Top Halve.
 * Work scheduled earlier is done now, here.
 */
static void netsfs_go(struct work_struct *work)
{
    struct netsfs_skb_info *netsfsinfo;
    struct dentry *mac_dentry, *network_dentry, *network_stats_dentry;

    netsfsinfo = container_of(work, struct netsfs_skb_info, my_work);

    printk("Worker: %s %s %d\n", netsfsinfo->mac_name, netsfsinfo->network_name, netsfsinfo->len);

    /* Create mac dir */
    netsfs_create_by_name(netsfsinfo->mac_name, S_IFDIR, NULL, &mac_dentry, NULL, NETSFS_DIR);
    /* Create top level stats and stream files */
    netsfs_create_by_name("stats", S_IFREG, NULL, &network_stats_dentry, NULL, NETSFS_STATS);
    netsfs_create_by_name("stream", S_IFREG, NULL, &network_stats_dentry, NULL, NETSFS_STREAM);

    if (mac_dentry) {
        netsfs_create_by_name("stats", S_IFREG, mac_dentry, &network_stats_dentry, NULL, NETSFS_STATS);
        netsfs_create_by_name("stream", S_IFREG, mac_dentry, &network_stats_dentry, NULL, NETSFS_STREAM);
        netsfs_create_by_name(netsfsinfo->network_name, S_IFDIR, mac_dentry, &network_dentry, NULL, NETSFS_DIR);
        if (network_dentry) {
            netsfs_create_by_name("stats", S_IFREG, network_dentry, &network_stats_dentry, NULL, NETSFS_STATS);
            netsfs_create_by_name("stream", S_IFREG, network_dentry, &network_stats_dentry, NULL, NETSFS_STREAM);
        }
    }

    /* Increment size of inode */
    netsfs_inc_inode_size(mac_dentry->d_parent->d_inode, netsfsinfo->len);
    netsfs_inc_inode_size(mac_dentry->d_inode, netsfsinfo->len);
    netsfs_inc_inode_size(network_dentry->d_inode, netsfsinfo->len);


    kfree( (void *) work);
}

/* Bottom Halve.
 * Grab the packet in Interrupt Context, we need be fast here.
 */
int netsfs_packet_handler(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
                          struct net_device *dev2)
{
    int len, err;
    struct netsfs_skb_info *netsfsinfo;
    char mac_name[8], network_name[6];

    len = skb->len;

    /* IEEE 802.3 Ethernet magic. */
    if (len > ETH_DATA_LEN) {
        err = -ENOMEM;
        goto free;
    }

    /* check for ip header, in this case never will get nothing different of ETH_P_IP, but this switch
     * is here just in case you change netsfs_pseudo_proto.type
     */
    switch (ntohs(eth_hdr(skb)->h_proto))
    {
        case ETH_P_IP:
            sprintf(mac_name, "0x%.4x", ntohs(eth_hdr(skb)->h_proto));
            sprintf(network_name, "0x%.2x", ip_hdr(skb)->protocol);
            break;
        case ETH_P_IPV6:
            sprintf(mac_name, "0x%.4x", ntohs(eth_hdr(skb)->h_proto));
            sprintf(network_name, "0x%.2x", ipv6_hdr(skb)->nexthdr);
            break;
        default:
            printk(KERN_INFO "%s: Unknow packet (0x%.4X, 0x%.4X)\n",
                    THIS_MODULE->name,
                    ntohs(pkt->type),
                    ntohs(eth_hdr(skb)->h_proto));
            err = -ENOMEM;
            goto free;
            break;
    }

    /* Put a work in a shared workqueue provided by the kernel */
    netsfsinfo = kzalloc(sizeof(struct netsfs_skb_info), GFP_ATOMIC);
    if (!netsfsinfo) {
        err = -ENOMEM;
        goto free;
    }

    netsfsinfo->len = len;
    strncpy(netsfsinfo->mac_name, mac_name, strlen(mac_name));
    strncpy(netsfsinfo->network_name, network_name, strlen(mac_name));
    INIT_WORK(&netsfsinfo->my_work, netsfs_go);
    schedule_work(&netsfsinfo->my_work);

free:
    dev_kfree_skb(skb);
    return err;
}
