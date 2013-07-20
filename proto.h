/* internal.h: netsfs protocol handler definitions
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

#ifndef __NETSFS_PROTO_H__
#define __NETSFS_PROTO_H__

extern void netsfs_register_pack(void);

int netsfs_packet_handler(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
                          struct net_device *dev2);

int get_transport_string(char *str, struct sk_buff *skb);
int get_network_string(char *str, struct sk_buff *skb);
int get_mac_string(char *str, struct sk_buff *skb);
#endif
