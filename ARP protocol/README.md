# 三種功能
##### 1.列出所有目前所接收到的ARP封包當中的目的IP位址和來源IP位址，並且實作過濾(filter)的功能。
![](https://i.postimg.cc/zftwc86S/2023-05-01-004217.png)
##### 2.向特定的IP位址請求MAC地址，實作方式為：首先建立兩個Process，父行程將ARP封包的表頭(header)填好需要的資訊再經由socket向廣播位址(0xff)傳送ARP請求，子行程接收來自目的IP位址的ARP回應包並列印出目的IP位址的MAC位址。
![](https://i.postimg.cc/sXPj2gz5/2023-05-01-005349.png)
##### 3.ARP spoofing，偽造目的IP位址的MAC位址，欺騙位於來源IP位址上的主機，實作方式為：等待接收到向特定IP位址請求MAC位址的ARP請求包之後，偽造MAC位址並傳送ARP回應包給來源主機。
![](https://i.postimg.cc/Fsz4MZYy/2023-05-01-005528.png)
