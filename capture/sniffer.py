# ============================================================================
# sniffer.py — 数据包捕获模块 (基于 Scapy + Npcap)
# ============================================================================
# 使用 Scapy 的 AsyncSniffer 在后台线程抓包, 通过 Queue 传递给流计量引擎。
# 生产者-消费者模式: 本模块是生产者, flow.meter 是消费者。

import queue
import threading
import time
from scapy.all import AsyncSniffer, conf
from scapy.interfaces import get_working_ifaces
from config.settings import CAPTURE, DEBUG, FILTER


class PacketCapture:
    """
    数据包捕获器
    ────────────
    职责: 在后台线程中嗅探网络接口, 将捕获的报文放入共享队列。
    仅捕获 IP 报文 (BPF: "ip"), 忽略 ARP 等非 IP 流量。
    """

    def __init__(self, packet_queue: queue.Queue):
        """
        初始化捕获器
        ────────────
        packet_queue: 共享队列, 用于将报文传递给流计量线程
        """
        self.packet_queue = packet_queue
        self.sniffer: AsyncSniffer = None  # Scapy 异步嗅探器实例
        self._stop_event = threading.Event()
        self._capture_thread = None
        self.packet_count = 0  # 已捕获报文计数
        self.interface = None  # 实际使用的网卡名

    def _list_interfaces(self) -> list:
        """列出所有可用网络接口(Windows)"""
        ifaces = get_working_ifaces()
        if DEBUG.get("verbose"):
            print(f"[可用网络接口]:")
            for i, iface in enumerate(ifaces):
                print(f"  [{i}] {iface.name} ({iface.description}) — {iface.ips}")
        return ifaces

    def _detect_interface(self) -> str:
        """
        自动检测最佳捕获网卡
        ────────────────────
        策略:
        1. 若 config 中指定了接口名, 直接使用
        2. 否则使用 Scapy 的 conf.iface (默认路由接口)
        3. 若仍为空, 列出所有接口让用户选择
        """
        specified = CAPTURE.get("interface")
        if specified:
            return specified

        # 尝试获取默认接口
        default_iface = conf.iface
        if default_iface and hasattr(default_iface, 'name'):
            name = default_iface.name
            if name and name != "any":
                return name

        # 回退: 列出接口
        ifaces = self._list_interfaces()
        if ifaces:
            return ifaces[0].name

        return conf.iface

    @staticmethod
    def build_bpf_filter(filter_config: dict) -> str:
        """
        构建 BPF 过滤器
        ──────────────
        将 FILTER["bpf"] 配置转换为 BPF 过滤表达式。
        条件为空/0 时自动忽略。
        示例:
          {"protocol": "TCP", "ip": "10.0.0.1", "src_port": 80}
          → "ip and tcp and host 10.0.0.1 and src port 80"
        """
        bpf = filter_config.get("bpf", filter_config)
        parts = ["ip"]

        if bpf.get("protocol"):
            parts.append(bpf["protocol"].lower())
        if bpf.get("ip"):
            parts.append(f"host {bpf['ip']}")
        if bpf.get("src_port"):
            parts.append(f"src port {bpf['src_port']}")
        if bpf.get("dst_port"):
            parts.append(f"dst port {bpf['dst_port']}")

        return " and ".join(parts)

    def start(self):
        """启动数据包捕获 (后台线程)"""
        self.interface = self._detect_interface()
        bpf = self.build_bpf_filter(FILTER)

        print(f"[数据包捕获] 网卡: {self.interface}, BPF: {bpf}")

        self._stop_event.clear()
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketCapture"
        )
        self._capture_thread.start()

    def stop(self):
        """停止数据包捕获"""
        self._stop_event.set()
        if self.sniffer:
            self.sniffer.stop()

    def _capture_loop(self):
        """
        捕获主循环
        ──────────
        使用 Scapy AsyncSniffer 在后台抓包, 将报文放入共享队列。
        """
        bpf = self.build_bpf_filter(FILTER)

        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf,
            prn=self._packet_handler,
            store=False,
        )

        self.sniffer.start()

        # 等待停止信号
        while not self._stop_event.is_set():
            time.sleep(0.5)

        self.sniffer.stop()

    def _packet_handler(self, pkt):
        """
        报文回调函数
        ────────────
        每捕获一个报文, Scapy 调用此函数。
        将报文放入共享队列供流计量线程消费。
        """
        try:
            self.packet_queue.put(pkt, timeout=1)
            self.packet_count += 1

            if DEBUG.get("log_packet_count") and self.packet_count % DEBUG["log_packet_count"] == 0:
                print(f"[数据包捕获] 已捕获 {self.packet_count} 个报文, "
                      f"队列长度: {self.packet_queue.qsize()}")
        except queue.Full:
            # 队列满, 丢弃报文 (防止内存溢出)
            if DEBUG.get("verbose"):
                print(f"[数据包捕获] 队列已满, 丢弃报文")
