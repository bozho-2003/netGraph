# netGraph
You gan graph the udp or rtp packet in a graph.
通过pcap抓包, 通过各种条件过滤出RTP报文, 获得RTP报文的端口号, 然后统计实际每秒的比特率, 通过类似心电图的形式展示出来.
可以用于流量监测, 编码器的码率控制等.
纯Python实现, 采用pcap抓包, 通过ply进行词法解析 语法解析, 通过matplotlib绘制图形,通过tkinter构成UI界面.
