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
        //根据dst ip获得neigh数据
	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
		/* if crossing protocols, can not use the cached header */
                //向neigh发送skb数据
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
        //如果是路由需要经过网关，查询网关neigh
	if (likely(rt->rt_gw_family == AF_INET)) {
		neigh = ip_neigh_gw4(dev, rt->rt_gw4);
	} else if (rt->rt_gw_family == AF_INET6) {
		neigh = ip_neigh_gw6(dev, &rt->rt_gw6);
		*is_v6gw = true;
	} else {
        //如果不需要直接查询dst ip的neigh
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
        //先查询，不存在就建立
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
        //两种方式，邻居状态是NUD_CONNECTED，非跳过cache的直接走mac缓存
	/* n->nud_state and hh->hh_len could be changed under us.
	 * neigh_hh_output() is taking care of the race later.
	 */
	if (!skip_cache &&
	    (READ_ONCE(n->nud_state) & NUD_CONNECTED) &&
	    READ_ONCE(hh->hh_len))
		return neigh_hh_output(hh, skb);
        //另外一种调用neigh成员函数output发送
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
                               //复制缓存的mac到skb
				memcpy(skb->data - HH_DATA_MOD, hh->hh_data,
				       HH_DATA_MOD);
			}
		} else {
			hh_alen = HH_DATA_ALIGN(hh_len);
                        //复制缓存的mac到skb
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
        //发送给下一层
	__skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}
```
这个函数的作用是复制`hh_cache`数据结构里面的`hh_data`到skb，然后通过dev_queue_xmit把数据传递给网络设备的发送队列。hh_data就是eth header里面包含源目的mac和协议，eth header的数据结构ethhdr如下：
```c
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));
```
hh_data是个数组，里面数据就是这个ethhdr。<br>
返回`neigh_output`看下neigh状态不是`NUD_CONNECTED`，会直接走neigh的成员函数`output`对skb的发送，现在确认下`output`对应的实际函数是哪个，顺着这个思路，要找到`output`的函数，需要先找到neigh的初始化构建函数，在上面代码获得neigh的里面有提到，回到neigh的创建`ip_neigh_gw4`里面的`__neigh_create`:
```c
static inline struct neighbour *ip_neigh_gw4(struct net_device *dev,
					     __be32 daddr)
{
	struct neighbour *neigh;

	neigh = __ipv4_neigh_lookup_noref(dev, (__force u32)daddr);
	if (unlikely(!neigh))
         //创建neigh
		neigh = __neigh_create(&arp_tbl, &daddr, dev, false);

	return neigh;
}
```
可以看到`__neigh_create`里面有全局参数arp_tbl，在详细可以在https://elixir.bootlin.com/linux/v5.15.63/source/net/ipv4/arp.c#L152 找到，如下是部分：
```c
struct neigh_table arp_tbl = {
	.family		= AF_INET,
	.key_len	= 4,
	.protocol	= cpu_to_be16(ETH_P_IP),
	.hash		= arp_hash,
	.key_eq		= arp_key_eq,
	.constructor	= arp_constructor,
	.proxy_redo	= parp_redo,
	.is_multicast	= arp_is_multicast,
```
继续进入`__neigh_create`
```c
static struct neighbour *
___neigh_create(struct neigh_table *tbl, const void *pkey,
		struct net_device *dev, u8 flags,
		bool exempt_from_gc, bool want_ref)
{
	u32 hash_val, key_len = tbl->key_len;
	struct neighbour *n1, *rc, *n;
	struct neigh_hash_table *nht;
	int error;

	n = neigh_alloc(tbl, dev, flags, exempt_from_gc);
	trace_neigh_create(tbl, dev, pkey, n, exempt_from_gc);
	if (!n) {
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}

	memcpy(n->primary_key, pkey, key_len);
	n->dev = dev;
	dev_hold(dev);

	/* Protocol specific setup. */
        //构建函数
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	if (dev->netdev_ops->ndo_neigh_construct) {
		error = dev->netdev_ops->ndo_neigh_construct(dev, n);
		if (error < 0) {
			rc = ERR_PTR(error);
			goto out_neigh_release;
		}
	}

	/* Device specific setup. */
	if (n->parms->neigh_setup &&
	    (error = n->parms->neigh_setup(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	n->confirmed = jiffies - (NEIGH_VAR(n->parms, BASE_REACHABLE_TIME) << 1);

	write_lock_bh(&tbl->lock);
	nht = rcu_dereference_protected(tbl->nht,
					lockdep_is_held(&tbl->lock));

	if (atomic_read(&tbl->entries) > (1 << nht->hash_shift))
		nht = neigh_hash_grow(tbl, nht->hash_shift + 1);

	hash_val = tbl->hash(n->primary_key, dev, nht->hash_rnd) >> (32 - nht->hash_shift);

	if (n->parms->dead) {
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}

	for (n1 = rcu_dereference_protected(nht->hash_buckets[hash_val],
					    lockdep_is_held(&tbl->lock));
	     n1 != NULL;
	     n1 = rcu_dereference_protected(n1->next,
			lockdep_is_held(&tbl->lock))) {
		if (dev == n1->dev && !memcmp(n1->primary_key, n->primary_key, key_len)) {
			if (want_ref)
				neigh_hold(n1);
			rc = n1;
			goto out_tbl_unlock;
		}
	}

	n->dead = 0;
	if (!exempt_from_gc)
		list_add_tail(&n->gc_list, &n->tbl->gc_list);

	if (want_ref)
		neigh_hold(n);
	rcu_assign_pointer(n->next,
			   rcu_dereference_protected(nht->hash_buckets[hash_val],
						     lockdep_is_held(&tbl->lock)));
	rcu_assign_pointer(nht->hash_buckets[hash_val], n);
	write_unlock_bh(&tbl->lock);
	neigh_dbg(2, "neigh %p is created\n", n);
	rc = n;
out:
	return rc;
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	if (!exempt_from_gc)
		atomic_dec(&tbl->gc_entries);
	neigh_release(n);
	goto out;
}

struct neighbour *__neigh_create(struct neigh_table *tbl, const void *pkey,
				 struct net_device *dev, bool want_ref)
{
	return ___neigh_create(tbl, pkey, dev, 0, false, want_ref);
}
EXPORT_SYMBOL(__neigh_create);
```
从上面代码找到一行`if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {`，这里constructor就是arp_tbl的constructor，对应的函数是`.constructor	= arp_constructor,`，这里明显就是neigh的初始化构建，继续进入arp_constructor
```c
static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr;
	struct net_device *dev = neigh->dev;
	struct in_device *in_dev;
	struct neigh_parms *parms;
	u32 inaddr_any = INADDR_ANY;

	if (dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
		memcpy(neigh->primary_key, &inaddr_any, arp_tbl.key_len);

	addr = *(__be32 *)neigh->primary_key;
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return -EINVAL;
	}

	neigh->type = inet_addr_type_dev_table(dev_net(dev), dev, addr);

	parms = in_dev->arp_parms;
	__neigh_parms_put(neigh->parms);
	neigh->parms = neigh_parms_clone(parms);
	rcu_read_unlock();
        //不存在dev->header_ops情况，如ipip虚拟设备
	if (!dev->header_ops) {
		neigh->nud_state = NUD_NOARP;
		neigh->ops = &arp_direct_ops;
		neigh->output = neigh_direct_output;
	} else {
        //存在的情况
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */

		if (neigh->type == RTN_MULTICAST) {
			neigh->nud_state = NUD_NOARP;
			arp_mc_map(addr, neigh->ha, dev, 1);
		} else if (dev->flags & (IFF_NOARP | IFF_LOOPBACK)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);
		} else if (neigh->type == RTN_BROADCAST ||
			   (dev->flags & IFF_POINTOPOINT)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);
		}
                //这里处理单播情况
		if (dev->header_ops->cache)
			neigh->ops = &arp_hh_ops;
		else
			neigh->ops = &arp_generic_ops;

		if (neigh->nud_state & NUD_VALID)
			neigh->output = neigh->ops->connected_output;
		else
			neigh->output = neigh->ops->output;
	}
	return 0;
}
```
看上面逻辑，先判断dev->header_ops是否存在`if (!dev->header_ops) {`(例如ipip设备就不存在header_ops)，如果不存在dev->header_ops，neigh实例的output为`neigh_direct_output`见代码`neigh->output = neigh_direct_output;`，如果存在从`if (dev->header_ops->cache)`往下看，neigh->ops被赋值为arp_hh_ops或者arp_generic_ops，后面的逻辑就是检查neigh状态是否为`NUD_VALID`，后面的`neigh->output`赋值为`neigh->ops->connected_output`或者`neigh->ops->ouput`,也就是有`dev->header_ops->cache`并且neigh状态是`NUD_VALID`，neigh->output为`arp_hh_ops->connect_output`,有`dev->header_ops->cache`并且neigh状态为非`NUD_VALID`，neigh->output为`arp_hh_ops->output`，没有`dev->header_ops->cache`的时候逻辑一样，换成`arp_generic_ops`，继续看下`arp_hh_ops`和`arp_generic_ops`变量
```c
static const struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
};

static const struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
};
```
可以看到neigh的output函数有三个可能
```c
neigh_direct_output;
neigh_resolve_output;
neigh_connected_output;
```
`neigh_direct_output`是不设置ethhdr直接发送，不是我们关注的场景，接下来看下`neigh_resolve_output`
```c
int neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc = 0;

	if (!neigh_event_send(neigh, skb)) {
		int err;
		struct net_device *dev = neigh->dev;
		unsigned int seq;

		if (dev->header_ops->cache && !READ_ONCE(neigh->hh.hh_len))
			neigh_hh_init(neigh);

		do {
			__skb_pull(skb, skb_network_offset(skb));
			seq = read_seqbegin(&neigh->ha_lock);
                        //注意这里参数中NULL
			err = dev_hard_header(skb, dev, ntohs(skb->protocol),
					      neigh->ha, NULL, skb->len);
		} while (read_seqretry(&neigh->ha_lock, seq));

		if (err >= 0)
			rc = dev_queue_xmit(skb);
		else
			goto out_kfree_skb;
	}
out:
	return rc;
out_kfree_skb:
	rc = -EINVAL;
	kfree_skb(skb);
	goto out;
}
EXPORT_SYMBOL(neigh_resolve_output);
```
可以看到有个`dev_hard_header`的函数调用，是设置skb的ethhdr，接着看下
```c
static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev,
				  unsigned short type,
				  const void *daddr, const void *saddr,
				  unsigned int len)
{
	if (!dev->header_ops || !dev->header_ops->create)
		return 0;

	return dev->header_ops->create(skb, dev, type, daddr, saddr, len);
}
```
可以在linux源码网站bootlin.com全局搜索下`header_ops`, 定位到Ethernet设备的header_ops在https://elixir.bootlin.com/linux/v5.15.63/source/net/ethernet/eth.c#L78 代码如下：
```c
const struct header_ops eth_header_ops ____cacheline_aligned = {
	.create		= eth_header,
	.parse		= eth_header_parse,
	.cache		= eth_header_cache,
	.cache_update	= eth_header_cache_update,
	.parse_protocol	= eth_header_parse_protocol,
};
```
可以看到header_ops->create对应函数是`eth_header`,继续看下eth_header
```c
int eth_header(struct sk_buff *skb, struct net_device *dev,
	       unsigned short type,
	       const void *daddr, const void *saddr, unsigned int len)
{
	struct ethhdr *eth = skb_push(skb, ETH_HLEN);

	if (type != ETH_P_802_3 && type != ETH_P_802_2)
		eth->h_proto = htons(type);
	else
		eth->h_proto = htons(len);

	/*
	 *      Set the source hardware address.
	 */
        //这里就是dev_hard_header调用传的NULL，直接赋值了接口mac
	if (!saddr)
		saddr = dev->dev_addr;
	memcpy(eth->h_source, saddr, ETH_ALEN);

	if (daddr) {
		memcpy(eth->h_dest, daddr, ETH_ALEN);
		return ETH_HLEN;
	}

	/*
	 *      Anyway, the loopback-device should never use this function...
	 */

	if (dev->flags & (IFF_LOOPBACK | IFF_NOARP)) {
		eth_zero_addr(eth->h_dest);
		return ETH_HLEN;
	}

	return -ETH_HLEN;
}
EXPORT_SYMBOL(eth_header);
```
可以看到会根据参数是否存在saddr，如果不存在就复制网卡的mac地址，`neigh_resolve_output`里面
```c
		do {
			__skb_pull(skb, skb_network_offset(skb));
			seq = read_seqbegin(&neigh->ha_lock);
			err = dev_hard_header(skb, dev, ntohs(skb->protocol),
					      neigh->ha, NULL, skb->len);
		} while (read_seqretry(&neigh->ha_lock, seq));
```
填的saddr是NULL，所以发出去的报文是本机的接口的mac地址，`neigh_connected_output`里面一样，dev_hard_header参数`void *saddr`填的也是`NULL`。<br>
至此，整个`ip_fininsh_ouput2`设置ethhdr，然后把将skb传递给网络设备的发送队列，将skb发送出去的逻辑就理清楚了，可以看到所有skb的源mac都会被设置为发送网卡的mac。
## 透明代理网桥模式下替换skb的源mac地址
网桥模式下，流量被重定向到应用层，应用层透明代理收到客户端发起的请求，模拟客户端发送到服务器端，收到服务器端响应，模拟服务器端响应客户端，这里面代理设置源ip为客户端ip，或者为服务器端ip，但是数据从客户端发送查询其路由表及邻居表封装的目的mac是网关的mac（服务器不在同网段）或者服务器mac，经过代理后，响应报文的源mac，客户端看到的不是其网关（服务器不在同网段）或者服务器mac，而是变成了代理的网桥的mac，服务器端看到的也是这种情况（服务器不在同网段，网关设备看到请求报文的源mac就变成了代理设备的网桥mac），同网段服务器看到的源mac变成代理设备的网桥mac。<br>
```
                         wlan0 (mgmt)
                           |
                        +------+
                        | HOST |
   +--------+           |------|             +--------+	            +--------+
   | CLIENT | <-- 1 --> | MITM | <--- 2 ---> | ROUTER | <--- 3 ---> | SERVER |
   +--------+           +------+             +--------+             +--------+
  192.168.1.31       /     br0    \         192.168.1.1             69.171.229.73
                 eth0 192.168.1.30 eth1
```
```
CLIENT route table
+-------------------------------------------------------------------------------+
| Destination     Gateway         Genmask         Flags Metric Ref    Use Iface |
| 0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 ens33 |
| 192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 ens33 |
| 192.168.1.1     0.0.0.0         255.255.255.255 UH    100    0        0 ens33 |
+-------------------------------------------------------------------------------+
CLIENT neigh table
+------------------------------------------------------+ 
| 192.168.1.1 dev ens33 lladdr 00:50:56:e2:4e:e3 STALE |
| 192.168.1.30 dev ens33 lladdr 00:50:56:e6:37:f5 STALE|
+------------------------------------------------------+
```
```
TCP PROXY netns MITM route table
+-------------------------------------------------------------------------------+
| Destination     Gateway         Genmask         Flags Metric Ref    Use Iface |
| 0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0   br0 |
| 192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0   br0 |
| 192.168.1.1     0.0.0.0         255.255.255.255 UH    100    0        0   br0 |
+-------------------------------------------------------------------------------+
CLIENT neigh table
+----------------------------------------------------+ 
| 192.168.1.1 dev br0 lladdr 00:50:56:e2:4e:e3 STALE |
| 192.168.1.31 dev br0 lladdr 00:50:56:c0:00:08 STALE|
+----------------------------------------------------+
```
```
CLIENT request package
+-------------------+-------------------+--------+-----------+---------------+---------------+----------+----------+------+
| dst mac           | src mac           | type   | ip header | src ip        | dst ip        | src port | dst port | data |
+-------------------+-------------------+--------+-----------+---------------+---------------+----------+----------+------+
| 00:50:56:e2:4e:e3 | 00:50:56:c0:00:08 | 0x0800 | 0x4500xx  | 192.168.31.31 | 69.171.229.73 | 64132    | 443      | 0xXX |
+-------------------+-------------------+--------+-----------+---------------+---------------+----------+----------+------+
```
```
CLIENT request package proxy by TCP PROXY 发出去的请求报文，源mac会变为br0的mac地址，源端口也会被改变（源端口不用关注）
+-------------------+-------------------+--------+-----------+--------------+---------------+----------+----------+------+
| dst mac           | src mac           | type   | ip header | src ip       | dst ip        | src port | dst port | data |
+-------------------+-------------------+--------+-----------+--------------+---------------+----------+----------+------+
| 00:50:56:e2:4e:e3 | 00:50:56:e6:37:f5 | 0x0800 | 0x4500xx  | 192.168.1.31 | 69.171.229.73 | 62122    | 443      | 0xXX |
+-------------------+-------------------+--------+-----------+--------------+---------------+----------+----------+------+
```
```
SERVER response package到达ROUTER后
+-------------------+-------------------+--------+-----------+---------------+--------------+----------+----------+------+
| dst mac           | src mac           | type   | ip header | src ip        | dst ip       | src port | dst port | data |
+-------------------+-------------------+--------+-----------+---------------+--------------+----------+----------+------+
| 00:50:56:c0:00:08 | 00:50:56:e2:4e:e3 | 0x0800 | 0x4500xx  | 69.171.229.73 | 192.168.1.31 | 443      | 62122    | 0xXX |
+-------------------+-------------------+--------+-----------+---------------+--------------+----------+----------+------+
```
```
SERVER response package proxy by TCP RPOXY
+-------------------+-------------------+--------+-----------+---------------+--------------+----------+----------+------+
| dst mac           | src mac           | type   | ip header | src ip        | dst ip       | src port | dst port | data |
+-------------------+-------------------+--------+-----------+---------------+--------------+----------+----------+------+
| 00:50:56:c0:00:08 | 00:50:56:e6:37:f5 | 0x0800 | 0x4500xx  | 69.171.229.73 | 192.168.1.31 | 443      | 64132    | 0xXX |
+-------------------+-------------------+--------+-----------+---------------+--------------+----------+----------+------+
```
可以看到无论是请求报文，还是响应报文，经过透明代理后，源ip是不变的，但是源mac都变成了代理主机网桥接口的mac地址。<br>
## 源mac地址保持不变patch的实现
那么经过PROXY后如何修改源mac保持不变，其实方案经过上面代码分析已经呼之欲出了，在透明代理的时候，应用层代理设置了源ip为CLIENT的ip，并且设置sock类型为transparent，所以在ip_finish_output2中skb的saddr是CILENT的ip，那么想办法查询neigh表，查询到skb saddr对应的mac地址就是CLIENT的mac，在调用dev_hard_header的时候，把参数saddr填充CLIENT的mac就可以了。<br>
服务器响应报文相对复杂点，需要考虑同网段和不同网段（过网关的情况），同网段情况，响应报文的saddr就是SERVER的ip，处理同CLIENT的请求报文，不同网段情况，saddr是SERVER的ip，而源mac需要的是网关的mac地址，此时需要根据saddr（SERVER ip）查询网关，然后再根据网关查询neigh表，获得mac地址，填入dev_hard_header的saddr参数就完成了源mac地址保持不变。
```c
diff --git a/net/ipv4/ip_output.c b/net/ipv4/ip_output.c
index 131066d03..9ed70983e 100644
--- a/net/ipv4/ip_output.c
+++ b/net/ipv4/ip_output.c
@@ -222,8 +222,39 @@ static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *s
 	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
 	if (!IS_ERR(neigh)) {
 		int res;
//在根据daddr查询获得neigh后，增加如下代码
+		struct inet_sock *inet;
+		struct iphdr *iph;
+		struct neighbour *saddr_neigh;
+		struct rtable *rt1;
 
 		sock_confirm_neigh(skb, neigh);
//判断skb是否属于sock
+		if (skb->sk) {
//获得inet_sk数据结构，根据transparent判断是否为透明代理（透明代理应用层socket调用会set）
+			inet = inet_sk(skb->sk);
+			if (inet->transparent) {
+				iph = ip_hdr(skb);
//如果根据daddr获得rt网关类型是AF_INET，也就daddr是要走网关的，那么saddr就是同网段的，直接查询skb源ip的neigh
+				if (rt->rt_gw_family == AF_INET) {
+					saddr_neigh = ip_neigh_gw4(dev, iph->saddr);
//其他daddr是同网段，根据源地址查询网关，如果到源地址需要走网关（也就是不同网段），应该根据网关地址查询源neigh，
//如果不需要走网关（也就是在同网关），那么直接根据saddr查询源neigh
+				}else {
+					rt1 = ip_route_output(net, iph->saddr, 0, 0, 0);
+					if (IS_ERR(rt1)) {
+						goto no_src_mac;
+					}
+					if (rt1->rt_gw_family == AF_INET)
+						saddr_neigh = ip_neigh_gw4(dev, rt1->rt_gw4);
+					else
+						saddr_neigh = ip_neigh_gw4(dev, iph->saddr);
+
+					ip_rt_put(rt1);
+				}
+				if (!IS_ERR(saddr_neigh)) {
//把saddr_neigh传入neigh_transparent_output，后续传给dev_hard_header
+					res = neigh_transparent_output(neigh, saddr_neigh, skb);
+					rcu_read_unlock_bh();
+					return res;
+				}
+
+			}
+		}
+no_src_mac:
 		/* if crossing protocols, can not use the cached header */
 		res = neigh_output(neigh, skb, is_v6gw);
 		rcu_read_unlock_bh();
```
再来看下neigh_transparent_output
```c
diff --git a/include/net/neighbour.h b/include/net/neighbour.h
index d5767e255..656682cbd 100644
--- a/include/net/neighbour.h
+++ b/include/net/neighbour.h
@@ -500,6 +500,38 @@ static inline int neigh_hh_output(const struct hh_cache *hh, struct sk_buff *skb
 	return dev_queue_xmit(skb);
 }
 
+static inline int neigh_transparent_output(struct neighbour *neigh, struct neighbour *saddr_neigh, struct sk_buff *skb)
+{
+	int rc = 0;
+
+	int err;
+	struct net_device *dev = neigh->dev;
+	unsigned int saddr_seq;
+	unsigned int seq;
+
+	do {
+		saddr_seq = read_seqbegin(&saddr_neigh->ha_lock);
+		do {
+			__skb_pull(skb, skb_network_offset(skb));
+			seq = read_seqbegin(&neigh->ha_lock);
//在这里把saddr的neigh的mac地址传了dev_hard_header
+			err = dev_hard_header(skb, dev, ntohs(skb->protocol),
+						  neigh->ha, saddr_neigh->ha, skb->len);
+		} while (read_seqretry(&neigh->ha_lock, seq));
+	} while (read_seqretry(&saddr_neigh->ha_lock, saddr_seq));
+
+	if (err >= 0)
+		rc = dev_queue_xmit(skb);
+	else
+		goto out_kfree_skb;
+
+out:
+	return rc;
+out_kfree_skb:
+	rc = -EINVAL;
+	kfree_skb(skb);
+	goto out;
+}
+
 static inline int neigh_output(struct neighbour *n, struct sk_buff *skb,
 			       bool skip_cache)
 {
```
