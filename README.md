# tcp transparent proxy and filter
网桥模式流量通过ebtables和iptables tproxy 重定向到应用层，进行proxy，然后在skb发出的最后一个网络层函数ip_finish_output2 patch内核使发出的package源mac地址是client的mac(request package)或者gateway的mac(response package)。
# L2 Bridge to L3 TPROXY Interception
## 拓扑如下：
![image](https://raw.githubusercontent.com/imatespl/tcp-transparent-proxy/master/transparent-proxy.svg)
## 拓扑描述：
### 网桥设置
tcpfilter程序运行在工作站和路由器中间的设备，设备上有三个网卡，一个无线网卡，在network default namespace，另外两个物理网卡eth0和eth1被配置到network namespace mitm，并组成网桥<br>
```bash
ip netns add mitm
ip link set dev eth0 netns mitm
ip link set dev eth1 netns mitm
ip netns exec mitm ip link set dev lo up
ip netns exec mitm ip link add name br0 type bridge
ip netns exec mitm ip link set eth0 master br0
ip netns exec mitm ip link set eth1 master br0
ip netns exec mitm brctl setfd br0 0
ip netns exec mitm ip link set eth0 up
ip netns exec mitm ip link set eth1 up
ip netns exec mitm ip link set br0 up
```

