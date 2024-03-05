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
继续跟踪，仅看ipv4的情况，调用是`neigh = ip_neigh_gw4(dev, rt->rt_gw4);`或者`neigh = ip_neigh_gw4(dev, ip_hdr(skb)->daddr);`，看下`ip_neigh_gw4`
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
上面函数逻辑，首先根据dev和daddr查询neigh，如果不存在，则建立neigh。<br>
先不继续跟踪`__neigh_create`，返回`ip_finish_output2`，继续往下看，会判断neigh是否有错误，如果正常，则会执行`sock_confirm_neigh`，然后执行`neigh_output`，这个函数是填充eth header，函数代码如下：
```c
static inline int neigh_output(struct neighbour *n, struct sk_buff *skb,
			       bool skip_cache)
{
	const struct hh_cache *hh = &n->hh;

	/* n->nud_state and hh->hh_len could be changed under us.
	 * neigh_hh_output() is taking care of the race later.
	 */
	if (!skip_cache &&
	    (READ_ONCE(n->nud_state) & NUD_CONNECTED) &&
	    READ_ONCE(hh->hh_len))
		return neigh_hh_output(hh, skb);

	return n->output(n, skb);
}
```
这个函数先判断neigh状态，如果是`NUD_CONNECTED`既邻居是建立好并且是已连接状态，直接通过`neigh_hh_output`，读取neigh的`hh_cache`（既eth headr）填充到skb，然后发送，看下源码：
```c
static inline int neigh_hh_output(const struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int hh_alen = 0;
	unsigned int seq;
	unsigned int hh_len;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = READ_ONCE(hh->hh_len);
		if (likely(hh_len <= HH_DATA_MOD)) {
			hh_alen = HH_DATA_MOD;

			/* skb_push() would proceed silently if we have room for
			 * the unaligned size but not for the aligned size:
			 * check headroom explicitly.
			 */
			if (likely(skb_headroom(skb) >= HH_DATA_MOD)) {
				/* this is inlined by gcc */
				memcpy(skb->data - HH_DATA_MOD, hh->hh_data,
				       HH_DATA_MOD);
			}
		} else {
			hh_alen = HH_DATA_ALIGN(hh_len);

			if (likely(skb_headroom(skb) >= hh_alen)) {
				memcpy(skb->data - hh_alen, hh->hh_data,
				       hh_alen);
			}
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	if (WARN_ON_ONCE(skb_headroom(skb) < hh_alen)) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	__skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}
```
这个函数的作用是复制`hh_cache`数据结构里面的`hh_data`到skb，然后通过dev_queue_xmit把数据传递给网络设备的发送队列。hh_data就是eth header里面包含源目的mac和协议，ethhdr数据结构如下：
```c
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));
```
hh_data就是这个ethhdr
