# Traceroute
### 首先發送一個UDP封包，將其TTL值設為1，到達第一個hop時因TTL值被減1，所以TTL值為0，這時會發送一個ICMP超時錯誤(Time Exceeded Message)回應包，裡面包含發送端的IP，由此原理再將TTL值往上增加1並送出UDP封包，若還未到目的IP位址主機的話，就會回傳ICMP包並顯示所經過的所有主機名稱和IP位址，直到收到ICMP目標端口不可達(Unreachable)的錯誤訊息回應包才停止。
