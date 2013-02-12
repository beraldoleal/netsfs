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
#include <linux/export.h>

#include "proto.h"
#include "internal.h"

int netsfs_packet_handler(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
                          struct net_device *dev2)
{

    int len, err;
    struct dentry *de_mac;
    struct dentry *de_network;
    struct dentry *de_transport;

    char mac_name[8], network_name[6];

    len = skb->len;
    if (len > ETH_DATA_LEN) {
        printk(KERN_INFO "%s:len > ETH_DATA_LEN!\n", THIS_MODULE->name);
        err = -ENOMEM;
        goto fail;
    }
    /* check for ip header, in this case never will get nothing different of ETH_P_IP, but this switch
 *      * is here just in case you change netsfs_pseudo_proto.type
 *           */
    switch (ntohs(eth_hdr(skb)->h_proto))
    {
        case ETH_P_IP:
            sprintf(mac_name, "0x%.4x", ntohs(eth_hdr(skb)->h_proto));
            sprintf(network_name, "0x%.2x", ip_hdr(skb)->protocol);
            printk(KERN_INFO "%s: (%s %d, %s, %s) Packet\n",
                   THIS_MODULE->name,
                    skb->dev->name,
                    skb->dev->type,
                    mac_name, network_name);
            netsfs_create_by_name(mac_name, S_IFDIR, NULL, &de_mac, NULL);
            if (de_mac)
                netsfs_create_by_name(network_name, S_IFDIR, de_mac, &de_network, NULL);
            break;
        case ETH_P_IPV6:
            sprintf(mac_name, "0x%.4x", ntohs(eth_hdr(skb)->h_proto));
            sprintf(network_name, "0x%.2x", ipv6_hdr(skb)->nexthdr);
            printk(KERN_INFO "%s: (%s %d %s, %s) Packet\n",
                   THIS_MODULE->name,
                    skb->dev->name,
                    skb->dev->type,
                    mac_name,
                    network_name);
            netsfs_create_by_name(mac_name, S_IFDIR, NULL, &de_mac, NULL);
            if (de_mac)
                netsfs_create_by_name(network_name, S_IFDIR, de_mac, &de_network, NULL);
            break;

        default:
            printk(KERN_INFO "%s: Unknow packet (0x%.4X, 0x%.4X)\n", THIS_MODULE->name, ntohs(pkt->type), ntohs(eth_hdr(skb)->h_proto));
            break;
    }

    /* We need free the skb, this is a copy! */
    dev_kfree_skb(skb);

    return 0;

fail:
    dev_kfree_skb(skb);
    return err;
}
