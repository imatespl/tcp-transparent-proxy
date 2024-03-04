# 本文档主要用于记录kernel_patch的实现
## host数据包发出的最后一个函数ip_finish_output2
看下ip_finish_output2的源码
```c
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	bool is_v6gw = false;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		skb = skb_expand_head(skb, hh_len);
		if (!skb)
			return -ENOMEM;
	}

	if (lwtunnel_xmit_redirect(dst->lwtstate)) {
		int res = lwtunnel_xmit(skb);

		if (res < 0 || res == LWTUNNEL_XMIT_DONE)
			return res;
	}

	rcu_read_lock_bh();
	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
		/* if crossing protocols, can not use the cached header */
		res = neigh_output(neigh, skb, is_v6gw);
		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb(skb);
	return -EINVAL;
}
```
这个函数的逻辑是根据skb目的ip地址和route table获得neigh，然后调用neigh_output，填充skb的ethhdr(源mac和目的mac及协议)，然后将skb传递给网络设备的发送队列，以便后续由网络设备的驱动程序（device driver）来实际发送。<br>
下面看下neigh是如何获得的，上面代码，获得neigh的是`neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);`，函数代码如下：
```c
static inline struct neighbour *ip_neigh_for_gw(struct rtable *rt,
						struct sk_buff *skb,
						bool *is_v6gw)
{
	struct net_device *dev = rt->dst.dev;
	struct neighbour *neigh;

	if (likely(rt->rt_gw_family == AF_INET)) {
		neigh = ip_neigh_gw4(dev, rt->rt_gw4);
	} else if (rt->rt_gw_family == AF_INET6) {
		neigh = ip_neigh_gw6(dev, &rt->rt_gw6);
		*is_v6gw = true;
	} else {
		neigh = ip_neigh_gw4(dev, ip_hdr(skb)->daddr);
	}
	return neigh;
}
```
上面逻辑是根据rt->rt_gw_family值是否是AF_INET/AF_INET6，AF_INET表明rt->rt_gw4（也就是网关）是ipv4的地址，AF_INET6表明rt->rt_gw6（ipv6路由表网关）是ipv6的地址，其他情况表明route table的网关不存在，表示是直连地址。上面代码逻辑就是如果route table的是网关，根据网关构建neigh，如果不是，根据skb的目的ip地址构建neigh。<br>
继续跟踪，仅看ipv4的情况，调用是`neigh = ip_neigh_gw4(dev, rt->rt_gw4);`或者`neigh = ip_neigh_gw4(dev, ip_hdr(skb)->daddr);`，看下`ip_neigh_gw4((struct net_device *dev, __be32 daddr)`
```c
static inline struct neighbour *ip_neigh_gw4(struct net_device *dev,
					     __be32 daddr)
{
	struct neighbour *neigh;

	neigh = __ipv4_neigh_lookup_noref(dev, (__force u32)daddr);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &daddr, dev, false);

	return neigh;
}
```
