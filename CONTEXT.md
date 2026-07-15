# Delray 流量分析

Delray 观测网络接口上的流量，并区分流量是否能归属到具体进程。

## Language

**未归属流量（Unattributed Traffic）**：
已捕获，但在观测时无法关联到具体进程 ID 的流量。该术语不假定流量必然来自某个用户进程。
_Avoid_：未知进程、其他进程流量
