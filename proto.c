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
    int    x;
};

static void netsfs_go(struct work_struct *work)
{
    struct netsfs_skb_info *netsfsinfo;

    netsfsinfo = container_of(work, struct netsfs_skb_info, my_work);

    printk("Worker: netsfsinfo.x = %d\n", netsfsinfo->x);
    kfree( (void *) work);
}

int netsfs_packet_handler(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
                          struct net_device *dev2)
{
    int len, err;
    struct dentry *de_mac;
    struct dentry *de_network;
    struct dentry *de_transport;

    struct netsfs_skb_info *netsfsinfo;

    char mac_name[8], network_name[6];

    len = skb->len;
    if (len > ETH_DATA_LEN) {
        printk(KERN_INFO "%s:len > ETH_DATA_LEN!\n", THIS_MODULE->name);
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

    netsfsinfo->x = 10;
    INIT_WORK(&netsfsinfo->my_work, netsfs_go);
    schedule_work(&netsfsinfo->my_work);

free:
    dev_kfree_skb(skb);
    return err;
}
