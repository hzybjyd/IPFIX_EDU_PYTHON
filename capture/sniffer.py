# ============================================================================
# sniffer.py — 数据包捕获模块 (基于 WinDivert WFP 内核层)
# ============================================================================
# 使用 pydivert (WinDivert) 在 WFP 内核层拦截所有数据包:
#   - 命中阻断规则的包: 在内核层丢弃 (不进入应用层)
#   - 未命中的包: 放行并转为 Scapy 对象放入共享队列供流计量
#
# 生产者-消费者模式: 本模块是生产者, flow.meter 是消费者。

import queue
import threading

from scapy.all import IP as ScapyIP
from config.settings import DEBUG, FILTER


class PacketCapture:
    """
    数据包捕获器 (WinDivert 版)
    ───────────────────────────
    职责:
    1. 通过 WinDivert 在 WFP 内核层拦截所有数据包
    2. 检查阻断规则, 命中的包在内核丢弃
    3. 未命中的包转为 Scapy 对象放入共享队列
    4. 提供 start/stop 生命周期管理

    兼容原接口: packet_queue, packet_count, start(), stop()
    """

    def __init__(self, packet_queue: queue.Queue, blocker=None):
        """
        初始化捕获器
        ────────────
        packet_queue: 共享队列, 用于将报文传递给流计量线程
        blocker: Blocker 实例 (可选), 提供阻断规则检查
        """
        self.packet_queue = packet_queue
        self.blocker = blocker
        self._stop_event = threading.Event()
        self._capture_thread = None
        self._packet_count_internal = 0
        self.interface = None  # 实际使用的网卡名 (WinDivert 默认自动选择)

    @property
    def packet_count(self) -> int:
        """已捕获报文总数 (已放行入队列的)"""
        if self.blocker:
            return self.blocker.reinjected_count
        return self._packet_count_internal

    @property
    def blocked_count(self) -> int:
        """被阻断的报文数"""
        if self.blocker:
            return self.blocker.blocked_count
        return 0

    def start(self):
        """启动数据包捕获"""
        if self.blocker:
            self.blocker.start()
            self.interface = "WinDivert (WFP 内核层)"
        else:
            # 无阻断器时使用独立的 WinDivert 捕获 (仅放行, 不阻断)
            self._stop_event.clear()
            self._capture_thread = threading.Thread(
                target=self._capture_loop_standalone,
                daemon=True, name="PacketCapture"
            )
            self._capture_thread.start()
            self.interface = "WinDivert (WFP 内核层, 无阻断)"

        print(f"[数据包捕获] 接口: {self.interface}")

    def stop(self):
        """停止数据包捕获"""
        self._stop_event.set()
        if self.blocker:
            self.blocker.stop()

    def _capture_loop_standalone(self):
        """
        独立捕获循环 (无阻断器模式)
        ──────────────────────────
        当没有 blocker 时, 使用 WinDivert 仅做捕获和放行。
        """
        import pydivert

        # 构建 BPF 等效的 WinDivert filter
        bpf_filter = self._build_wdivert_filter(FILTER.get("bpf", {}))

        try:
            w = pydivert.WinDivert(bpf_filter)
            w.open()
        except Exception as e:
            print(f"[数据包捕获] WinDivert 打开失败: {e}")
            print(f"[数据包捕获] 请确认已以管理员权限运行")
            return

        print(f"[数据包捕获] WinDivert 已启动, filter: {bpf_filter}")

        while not self._stop_event.is_set():
            try:
                pkt = w.recv()
            except Exception:
                if self._stop_event.is_set():
                    break
                continue

            try:
                raw = bytes(pkt.raw)

                # 非 IPv4 包: 直接放行, 不入队列
                if not self._is_ipv4(raw):
                    w.send(pkt, recalculate_checksum=False)
                    continue

                # 回环流量: 直接放行, 不入队列
                if self._is_loopback(raw):
                    w.send(pkt, recalculate_checksum=False)
                    continue

                w.send(pkt, recalculate_checksum=False)
                self._forward_to_queue(raw)
            except Exception:
                continue

        try:
            w.close()
        except Exception:
            pass

    def _forward_to_queue(self, raw: bytes):
        """将原始报文转为 Scapy 对象并放入队列"""
        try:
            pkt = ScapyIP(raw)
            self.packet_queue.put(pkt, timeout=1)
            self._packet_count_internal += 1

            if DEBUG.get("log_packet_count") and self._packet_count_internal % DEBUG["log_packet_count"] == 0:
                print(f"[数据包捕获] 已捕获 {self._packet_count_internal} 个报文, "
                      f"队列长度: {self.packet_queue.qsize()}")
        except queue.Full:
            if DEBUG.get("verbose"):
                print(f"[数据包捕获] 队列已满, 丢弃报文")
        except Exception:
            pass

    @staticmethod
    def _build_wdivert_filter(bpf_config: dict) -> str:
        """
        将 BPF 筛选配置转换为 WinDivert filter 表达式
        ──────────────────────────────────────────────
        BPF 配置: {"ip": "", "protocol": "", "src_port": 0, "dst_port": 0}
        """
        parts = []
        proto = bpf_config.get("protocol", "").strip().upper()
        ip = bpf_config.get("ip", "").strip()
        src_port = int(bpf_config.get("src_port", 0))
        dst_port = int(bpf_config.get("dst_port", 0))

        if proto == "TCP":
            parts.append("tcp")
        elif proto == "UDP":
            parts.append("udp")
        elif proto == "ICMP":
            parts.append("icmp")

        if ip:
            parts.append(f"(ip.SrcAddr == {ip} or ip.DstAddr == {ip})")

        if src_port:
            port_filters = []
            if proto != "UDP":
                port_filters.append(f"tcp.SrcPort == {src_port}")
            if proto != "TCP":
                port_filters.append(f"udp.SrcPort == {src_port}")
            if port_filters:
                parts.append(f"({' or '.join(port_filters)})")

        if dst_port:
            port_filters = []
            if proto != "UDP":
                port_filters.append(f"tcp.DstPort == {dst_port}")
            if proto != "TCP":
                port_filters.append(f"udp.DstPort == {dst_port}")
            if port_filters:
                parts.append(f"({' or '.join(port_filters)})")

        return " and ".join(parts) if parts else "true"

    @staticmethod
    def _is_ipv4(raw: bytes) -> bool:
        """检查原始字节是否为 IPv4 报文"""
        if len(raw) < 20:
            return False
        return (raw[0] >> 4) & 0xF == 4

    @staticmethod
    def _is_loopback(raw: bytes) -> bool:
        """检查 IPv4 报文是否为回环流量 (127.x.x.x)"""
        if len(raw) < 20:
            return False
        return raw[12] == 127 or raw[16] == 127
