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
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/workqueue.h>
#include <linux/export.h>

#include "proto.h"
#include "internal.h"

struct netsfs_skb_info {
    struct work_struct my_work;
    struct sk_buff *skb;
};


/* Return the Ethernet Packet "Type" field in string.
 */
const char *get_ether_type(struct sk_buff *skb)
{
    switch (ntohs(eth_hdr(skb)->h_proto))
    {
        case ETH_P_IP:
            return "ipv4";
            break;
        case ETH_P_IPV6:
            return "ipv6";
            break;
        default:
            return "unknow";
            break;
    }
}


const char *get_ipv4_protocol(struct sk_buff *skb)
{
    switch (ip_hdr(skb)->protocol)
    {
        case IPPROTO_IP:
            return "ip";
            break;
        case IPPROTO_ICMP:
            return "icmp";
            break;
        case IPPROTO_IGMP:
            return "igmp";
            break;
        case IPPROTO_IPIP:
            return "ipip";
            break;
        case IPPROTO_TCP:
            return "tcp";
            break;
        case IPPROTO_UDP:
            return "udp";
            break;
        case IPPROTO_IPV6:
            return "ipv6"; /* ipv6 over ipv4 */
            break;
        case IPPROTO_SCTP:
            return "sctp";
            break;
        case IPPROTO_RAW:
            return "raw";
            break;
        default:
            return "unknow";
            break;
    }
}

const char *get_ipv6_protocol(struct sk_buff *skb)
{
    switch (ipv6_hdr(skb)->nexthdr)
    {
        case NEXTHDR_HOP:
            return "hop";
            break;
        case NEXTHDR_TCP:
            return "tcp";
            break;
        case NEXTHDR_UDP:
            return "udp";
            break;
        case NEXTHDR_IPV6:
            return "ipv6";
            break;
        case NEXTHDR_ICMP:
            return "icmp";
            break;
        default:
            return "unknow";
            break;
    }
}

/* Return the IP "protocol" field in string.
 */
const char *get_ip_protocol(struct sk_buff *skb)
{

    switch (ntohs(eth_hdr(skb)->h_proto))
    {
        case ETH_P_IP:
            return get_ipv4_protocol(skb);
        case ETH_P_IPV6:
            return get_ipv6_protocol(skb);
        default:
            return NULL;
            break;
    }
}

const char *get_application_protocol(struct sk_buff *skb)
{
    struct tcphdr *tcp_hdr;
    struct iphdr *ip_hdr;

    if (!skb)
        return NULL;

    /* Get ip header
     */
    ip_hdr = (struct iphdr *)skb_network_header(skb);
    if (!ip_hdr)
        return NULL;

    /* Get tcp header and checks if is TCP or UDP
     */
    tcp_hdr = (struct tcphdr *)((__u32 *)ip_hdr + ip_hdr->ihl);
    if ((!ip_hdr->protocol==IPPROTO_TCP) &&
        (!ip_hdr->protocol==IPPROTO_UDP))
        return NULL;

    /* TODO: Remove the hardcoded ports */
    if ((ntohs(tcp_hdr->dest) == 22) ||
        (ntohs(tcp_hdr->source) == 22))
        return "ssh";
    else if ((ntohs(tcp_hdr->dest) == 80) ||
        (ntohs(tcp_hdr->source) == 80))
        return "http";
    else if ((ntohs(tcp_hdr->dest) == 443) ||
        (ntohs(tcp_hdr->source) == 443))
        return "https";
    else if ((ntohs(tcp_hdr->dest) == 3306) ||
        (ntohs(tcp_hdr->source) == 3306))
        return "mysql";
    else {
        printk("netsfs: Unknow app protocol: %d, %d\n", ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest));
        return "unknow";
    }
}

/* Return skb len.
 */
unsigned int get_skb_len(struct sk_buff *skb)
{
    return skb->len;
}

/* Top Halve.
 * Work scheduled earlier is done now, here.
 */
static void netsfs_top(struct work_struct *work)
{
    struct netsfs_skb_info *netsfsinfo;
    struct dentry *network_dentry, *transport_dentry, *app_dentry;
    unsigned int len;

    netsfsinfo = container_of(work, struct netsfs_skb_info, my_work);
    len = get_skb_len(netsfsinfo->skb);

    /* Create top level files */
    netsfs_create_files(NULL);

    /* Create L3 dir */
    netsfs_create_dir(get_ether_type(netsfsinfo->skb), NULL, &network_dentry);

    if (network_dentry) {
        /* Create L3 files */
        netsfs_create_files(network_dentry);

        netsfs_inc_inode_size(network_dentry->d_parent->d_inode, len);
        netsfs_inc_inode_size(network_dentry->d_inode, len);

        /* Create L4 dir */
        netsfs_create_dir(get_ip_protocol(netsfsinfo->skb), network_dentry, &transport_dentry);
        if (transport_dentry) {
            /* Create L4 files */
            netsfs_create_files(transport_dentry);

            netsfs_inc_inode_size(transport_dentry->d_inode, len);

            /* TODO: Currently, L5 only for TCP. */
            if (ip_hdr(netsfsinfo->skb)->protocol == IPPROTO_TCP) {
                netsfs_create_dir(get_application_protocol(netsfsinfo->skb), transport_dentry, &app_dentry);
                if (app_dentry) {
                    netsfs_create_files(app_dentry);
                    netsfs_inc_inode_size(app_dentry->d_inode, len);
                }
            }
        }
    }


    /* Free stuff */
    dev_kfree_skb(netsfsinfo->skb);
    kfree( (void *) work);
}

/* Bottom Halve.
 * Grab the packet in Interrupt Context, we need be fast here.
 * Only filter some packet types and sends to a work queue do the job.
 */
int netsfs_packet_handler(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
                          struct net_device *dev2)
{
    unsigned int len;
    struct netsfs_skb_info *netsfsinfo;

    len = get_skb_len(skb);

    /* IEEE 802.3 Ethernet magic. */
    if (len > ETH_DATA_LEN) {
        dev_kfree_skb(skb);
        return -ENOMEM;
    }

    /* Currently we are only watching ETH_P_IP and ETH_P_IPV6.
     */
    switch (ntohs(eth_hdr(skb)->h_proto))
    {
        case ETH_P_IP:
        case ETH_P_IPV6:
            /* Put a work in a shared workqueue provided by the kernel */
            netsfsinfo = kzalloc(sizeof(struct netsfs_skb_info), GFP_ATOMIC);
            if (!netsfsinfo) {
                dev_kfree_skb(skb);
                return -ENOMEM;
            }

            netsfsinfo->skb = skb;
            INIT_WORK(&netsfsinfo->my_work, netsfs_top);
            schedule_work(&netsfsinfo->my_work);

            break;
        default:
            printk(KERN_INFO "%s: Unknow packet (0x%.4X, 0x%.4X)\n",
                    THIS_MODULE->name,
                    ntohs(pkt->type),
                    ntohs(eth_hdr(skb)->h_proto));
            dev_kfree_skb(skb);
            return -ENOMEM;
    }
    return 0;
}
