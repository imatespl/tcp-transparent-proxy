# tcp transparent proxy and filter
网桥模式流量通过ebtables和iptables tproxy 重定向到应用层，进行proxy，然后在skb发出的最后一个网络层函数ip_finish_output2 patch内核使发出的package源mac地址是client的mac(request package)或者gateway的mac(response package)。
# L2 Bridge to L3 TPROXY Interception
## 拓扑如下：
![image](https://raw.githubusercontent.com/imatespl/tcp-transparent-proxy/master/transparent-proxy.svg)
## 拓扑描述：
### 网桥设置
tcpfilter程序运行在工作站和路由器中间的设备，设备上有三个网卡，一个无线网卡，在network default namespace，另外两个物理网卡eth0和eth1被配置到network namespace mitm，并组成网桥，非tcpfilter关心的流量就可以直接通过网桥转发了。<br>
```bash
ip netns add mitm
ip link set dev eth0 netns mitm
ip link set dev eth1 netns mitm
# 进入mitm namespace，配置网桥
ip netns exec mitm /bin/bash
ip link set dev lo up
ip link add name br0 type bridge
ip link set eth0 master br0
ip link set eth1 master br0
brctl setfd br0 0
ip link set eth0 up
ip link set eth1 up
ip link set br0 up
```
### 流量劫持
进入到设备的流量需要通过etbtables策略和br_netfilter iptables TRPOXY策略重定向到tcpfilter进行处理，具体设置如下：
```bash
# 还是在mitm namespace
# 建立route table，tcpfilter的流量会走这个route table
export MARK=1
export TABLE_ID=100
echo "$TABLE_ID    tcpfilter" >> /etc/iproute2/rt_tables
# 被打标记的包，走tcpfilter的rt_tables
ip rule add fwmark $MARK lookup $TABLE_ID
ip route add local default dev lo table $TABLE_ID
# 加载br_netfilter
modprobe br_netfilter
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

# 禁止 return path filtering
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$CLIENT_IF/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$SERVER_IF/rp_filter

# 添加ebtables和iptables策略
ebtables -t broute -A BROUTING  -p ipv4 --ip-proto tcp  \
-j redirect --redirect-target DROP
iptables -t mangle -I PREROUTING -p tcp -j TPROXY \
--tproxy-mark $MARK --on-port 10999 --on-ip 127.0.0.1
```
流量会被重定向到10999端口，tcpfilter作为server监听10999端口，收到工作站主机发出的所有TCP流量，tcpfilter作为代理会模拟工作站作为client向工作站访问的server发起请求，传统代理会将工作站的请求报文的源ip和源mac都替换为代理程序所在主机的ip和mac，透明代理则会将请求报文的源ip替换工作站ip，但是源mac还是代理程序所在主机mac。响应报文源mac会从路由器网关的mac变为代理程序所在主机的mac。kernel_patch目录实现是完全隐藏源mac，请求报文的源mac经过tcpfilter后，会被替换为工作站mac响应报文源mac会被改为路由器网关的mac，达到完全隐藏代理。抓包看就是工作站和路由器直接通信。

