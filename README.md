# tcp transparent proxy and filter
网桥模式流量通过ebtables和iptables tproxy 重定向到应用层，进行proxy，然后在skb发出的最后一个函数ip_finish_output2 patch内核使发布的package源mac地址是client的mac(request package)或者gateway的mac(response package).
