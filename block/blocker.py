# ============================================================================
# blocker.py — WinDivert 内核级阻断引擎
# ============================================================================
# 职责:
#   1. 通过 WinDivert 在 WFP 内核层拦截所有数据包
#   2. 对命中的报文不调用 send()，使其在内核层被丢弃
#   3. 对未命中的报文调用 send() 放行，并转为 Scapy 对象入队供流计量
#   4. 统计阻断事件，记录最近阻断记录供 UI 展示

import struct
import threading
import time
import queue
from scapy.all import IP as ScapyIP
from block.rules import RuleManager


class Blocker:
    """
    WinDivert 内核级阻断器
    ─────────────────────
    工作流程:
      1. open("true") 拦截所有数据包
      2. recv() 接收包 → 解析 header → 检查规则
      3. 命中规则: 不调用 send()，包在内核被丢弃
      4. 未命中: send() 放行 + IP(raw) 入队列给 FlowMeter
    """

    def __init__(self, rule_manager: RuleManager, packet_queue: queue.Queue,
                 recent_max: int = 50):
        self.rule_manager = rule_manager
        self.packet_queue = packet_queue
        self.recent_max = recent_max

        self._stop_event = threading.Event()
        self._thread = None
        self._w = None  # WinDivert handle

        # 统计
        self.blocked_count = 0
        self.reinjected_count = 0
        self.recent_blocked: list[dict] = []  # 最近阻断事件
        self._stats_lock = threading.Lock()

    def start(self):
        """启动阻断器线程"""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="Blocker"
        )
        self._thread.start()

    def stop(self):
        """停止阻断器"""
        self._stop_event.set()
        if self._w:
            try:
                self._w.close()
            except Exception:
                pass

    def get_stats(self) -> dict:
        with self._stats_lock:
            return {
                "blocked": self.blocked_count,
                "reinjected": self.reinjected_count,
                "rules_enabled": len(self.rule_manager.get_enabled_rules()),
            }

    def get_recent_blocked(self) -> list[dict]:
        with self._stats_lock:
            return list(self.recent_blocked)

    # ─────────────────────────────────────────────────────────────
    #  主循环
    # ─────────────────────────────────────────────────────────────

    def _run(self):
        """阻断器主循环: 拦截 → 检查 → 放行或丢弃"""
        import pydivert

        # 构建 WinDivert filter
        # BPF 作为捕获过滤器 (内核层缩小捕获范围)
        # 阻断规则在 Python 层检查 (对捕获到的包做匹配后 drop)
        bpf_part = self._build_bpf_filter()
        w_filter = bpf_part if bpf_part else "true"

        try:
            self._w = pydivert.WinDivert(w_filter)
            self._w.open()
        except Exception as e:
            print(f"[阻断] WinDivert 打开失败: {e}")
            print(f"[阻断] 请确认已以管理员权限运行，且已安装 WinDivert 驱动")
            return

        print(f"[阻断] WinDivert 已启动, filter: {w_filter}")
        print("[阻断] 内核阻断引擎就绪 [OK]")

        while not self._stop_event.is_set():
            try:
                pkt = self._w.recv()
            except Exception:
                if self._stop_event.is_set():
                    break
                continue

            try:
                raw = bytes(pkt.raw)
                pkt_info = self._parse_raw(raw)

                # 非 IPv4 包: 直接放行, 不入队列
                if pkt_info is None:
                    self._w.send(pkt, recalculate_checksum=False)
                    continue

                # 回环流量: 直接放行, 不入队列
                if pkt_info["src_ip"].startswith("127.") or pkt_info["dst_ip"].startswith("127."):
                    self._w.send(pkt, recalculate_checksum=False)
                    continue

                # 命中阻断规则: 不调用 send()，包在内核被丢弃
                if self._is_blocked(pkt_info):
                    self._record_blocked(pkt_info)
                    continue

                # 未命中: 放行并入队列
                self._w.send(pkt, recalculate_checksum=False)
                self._forward_to_queue(raw)
            except Exception:
                continue

        # 清理
        try:
            self._w.close()
        except Exception:
            pass
        self._w = None

    # ─────────────────────────────────────────────────────────────
    #  报文解析 (轻量级, 不依赖 Scapy 全量解析)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_raw(raw: bytes) -> dict | None:
        """
        从原始字节解析 IP/TCP/UDP 头部关键字段
        ────────────────────────────────────────
        仅解析用于规则匹配的字段 (IP/端口/协议), 避免 Scapy 全量解析的开销。
        """
        if len(raw) < 20:
            return None

        version = (raw[0] >> 4) & 0xF
        if version != 4:
            return None

        ihl = (raw[0] & 0xF) * 4
        if ihl < 20 or len(raw) < ihl:
            return None

        protocol = raw[9]
        src_ip = f"{raw[12]}.{raw[13]}.{raw[14]}.{raw[15]}"
        dst_ip = f"{raw[16]}.{raw[17]}.{raw[18]}.{raw[19]}"

        src_port = 0
        dst_port = 0

        if protocol == 6 and len(raw) >= ihl + 20:  # TCP
            src_port = struct.unpack_from("!H", raw, ihl)[0]
            dst_port = struct.unpack_from("!H", raw, ihl + 2)[0]
        elif protocol == 17 and len(raw) >= ihl + 8:  # UDP
            src_port = struct.unpack_from("!H", raw, ihl)[0]
            dst_port = struct.unpack_from("!H", raw, ihl + 2)[0]

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        }

    def _is_blocked(self, pkt_info: dict) -> bool:
        """检查报文是否命中阻断规则"""
        hit, _ = self.rule_manager.match(pkt_info)
        return hit

    def _record_blocked(self, pkt_info: dict):
        """记录阻断事件"""
        with self._stats_lock:
            self.blocked_count += 1
            self.recent_blocked.append({
                "time": time.time(),
                "src_ip": pkt_info["src_ip"],
                "dst_ip": pkt_info["dst_ip"],
                "src_port": pkt_info["src_port"],
                "dst_port": pkt_info["dst_port"],
                "protocol": pkt_info["protocol"],
            })
            if len(self.recent_blocked) > self.recent_max:
                self.recent_blocked.pop(0)

    def _forward_to_queue(self, raw: bytes):
        """将放行的报文转为 Scapy 对象, 放入共享队列"""
        try:
            pkt = ScapyIP(raw)
            self.packet_queue.put(pkt, timeout=1)
            with self._stats_lock:
                self.reinjected_count += 1
        except Exception:
            pass

    @staticmethod
    def _build_bpf_filter() -> str:
        """将 BPF 筛选配置转为 WinDivert filter 表达式"""
        from config.settings import FILTER
        bpf = FILTER.get("bpf", {})
        parts = []
        proto = bpf.get("protocol", "").strip().upper()
        ip = bpf.get("ip", "").strip()
        src_port = int(bpf.get("src_port", 0))
        dst_port = int(bpf.get("dst_port", 0))

        if proto == "TCP":
            parts.append("tcp")
        elif proto == "UDP":
            parts.append("udp")
        elif proto == "ICMP":
            parts.append("icmp")

        if ip:
            parts.append(f"(ip.SrcAddr == {ip} or ip.DstAddr == {ip})")
        if src_port:
            pf = []
            if proto != "UDP":
                pf.append(f"tcp.SrcPort == {src_port}")
            if proto != "TCP":
                pf.append(f"udp.SrcPort == {src_port}")
            if pf:
                parts.append(f"({' or '.join(pf)})")
        if dst_port:
            pf = []
            if proto != "UDP":
                pf.append(f"tcp.DstPort == {dst_port}")
            if proto != "TCP":
                pf.append(f"udp.DstPort == {dst_port}")
            if pf:
                parts.append(f"({' or '.join(pf)})")

        return " and ".join(parts) if parts else ""
