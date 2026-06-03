# ============================================================================
# settings.py — 基于 IPFIX 的流计量系统 集中配置文件
# ============================================================================
# 所有可调参数集中于此, 便于统一管理和实验对比。

# ---------- 数据包捕获配置 ----------
CAPTURE = {
    "interface": None,          # None = 自动检测默认网卡; 也可指定如 "Ethernet"
    "bpf_filter": "ip",         # Berkeley Packet Filter: 仅捕获 IPv4 报文
    "snap_len": 65535,           # 捕获快照长度 (最大)
    "promisc": True,             # 是否开启混杂模式
}

# ---------- 流计量配置 ----------
FLOW = {
    "idle_timeout": 30,         # 空闲超时 (秒) — 该时间内无新报文则流过期
    "active_timeout": 300,      # 活跃超时 (秒) — 流最长存活时间
    "max_flows": 10000,         # 流表最大容量, 超限时强制清理最旧流
    "tcp_timeout_on_rst": True, # 收到 TCP RST 立即过期
    "tcp_timeout_on_fin": True, # 收到 TCP FIN 立即过期
}

# ---------- IPFIX 导出配置 ----------
IPFIX = {
    "collector_host": "127.0.0.1",   # IPFIX Collector 地址
    "collector_port": 4739,           # IPFIX 标准端口
    "export_interval": 10,            # 导出间隔 (秒)
    "observation_domain_id": 1,       # 观测域 ID
    "template_id": 256,               # Flow Template ID (>=256)
    "template_resend_interval": 10,   # 每 N 次数据导出后重发模板
    "export_file_enabled": True,      # 是否同时导出到文件
    "export_file_dir": "./ipfix_data",# 导出文件目录
}

# ---------- 展现配置 ----------
DISPLAY = {
    "refresh_interval": 2.0,    # 控制台刷新间隔 (秒)
    "max_active_flows_show": 20, # 最多显示的活跃流条数
}

# ---------- 筛选配置 ----------
# 筛选条件为空/0 即表示不筛选；无 ON/OFF 开关。
FILTER = {
    # 显示层筛选 — 仅过滤控制台展现 (即时生效, 不影响捕获)
    "display": {
        "ip": "",           # IP (匹配源或目的)
        "protocol": "",     # "TCP"/"UDP"/"ICMP"/""
        "src_port": 0,      # 源端口 (0=不筛选)
        "dst_port": 0,      # 目的端口 (0=不筛选)
    },
    # BPF 捕获层筛选 — 在捕获层过滤报文 (需重启嗅探器生效)
    "bpf": {
        "ip": "",           # IP (BPF: host xxx)
        "protocol": "",     # "TCP"/"UDP"/"ICMP"/""
        "src_port": 0,      # 源端口 (BPF: src port xxx)
        "dst_port": 0,      # 目的端口 (BPF: dst port xxx)
    },
}

# ---------- 调试配置 ----------
DEBUG = {
    "verbose": False,           # 是否打印详细日志
    "log_packet_count": 1000,   # 每 N 个包打印一次进度
}
