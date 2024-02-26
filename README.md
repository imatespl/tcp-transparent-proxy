# tcp transparent proxy and filter
网桥模式流量通过ebtables和iptables tproxy 重定向到应用层，进行proxy，然后在skb发出的最后一个网络层函数ip_finish_output2 patch内核使发出的package源mac地址是client的mac(request package)或者gateway的mac(response package)。
# L2 Bridge to L3 TPROXY Interception
## 拓扑如下：
![image](https://raw.githubusercontent.com/imatespl/tcp-transparent-proxy/master/transparent-proxy.svg)
