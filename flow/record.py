# ============================================================================
# record.py — 流记录数据结构定义
# ============================================================================
# 流 (Flow) 是由 5-tuple 唯一标识的一组报文集合。
# IPFIX 标准中, 流被定义为"在一定时间间隔内, 通过观测点的具有共同属性的报文集合"。

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple
import time


# ==================== 5-tuple 流键 ====================

class FlowKey(NamedTuple):
    """
    流标识五元组 — 唯一确定一条网络流
    ┌──────────────┬─────────────────────────────┐
    │ 字段         │ 说明                         │
    ├──────────────┼─────────────────────────────┤
    │ src_ip       │ 源 IPv4 地址 (字符串形式)     │
    │ dst_ip       │ 目的 IPv4 地址               │
    │ src_port     │ 源传输层端口 (0 表示无端口)    │
    │ dst_port     │ 目的传输层端口                │
    │ protocol     │ IP 协议号 (6=TCP, 17=UDP, 1=ICMP) │
    └──────────────┴─────────────────────────────┘
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __repr__(self):
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(self.protocol, str(self.protocol))
        return (f"{self.src_ip}:{self.src_port} → "
                f"{self.dst_ip}:{self.dst_port} [{proto_name}]")


# ==================== 流状态枚举 ====================

class FlowState(Enum):
    """
    流生命周期状态机
    ────────────────
    NEW      ──→ ACTIVE ──→ EXPIRED ──→ EXPORTED
                   │                        │
                   └──(超时/TCP FIN/RST)────┘
    """
    NEW = auto()       # 刚建立, 仅收到第一个报文
    ACTIVE = auto()    # 活跃中, 持续收到报文
    EXPIRED = auto()   # 已过期 (空闲超时/活跃超时/TCP结束)
    EXPORTED = auto()  # 已通过 IPFIX 导出


# ==================== 流记录 ====================

@dataclass
class FlowRecord:
    """
    流记录 — 存储一条流的所有统计信息
    ─────────────────────────────────
    对应 IPFIX 中的 Flow Data Record, 每个字段对应一个 IPFIX Information Element。
    """

    # ── 流标识 (Flow Key) ──
    key: FlowKey

    # ── 报文与字节计数 ──
    packet_count: int = 0
    byte_count: int = 0

    # ── 时间戳 ──
    flow_start_ms: float = field(default_factory=lambda: time.time() * 1000)
    flow_end_ms: float = field(default_factory=lambda: time.time() * 1000)

    # ── TCP 标志位累积 ──
    tcp_flags: int = 0   # 累积 OR: FIN=0x01 SYN=0x02 RST=0x04 ACK=0x10

    # ── 流状态 ──
    state: FlowState = FlowState.NEW

    def update(self, pkt_size: int, tcp_flags: int = 0):
        """
        更新流统计
        ──────────
        每收到一个属于此流的新报文时调用:
        - 累加报文数和字节数
        - 更新最后活动时间
        - 推进流状态 (NEW → ACTIVE)
        - 累积 TCP 标志位
        """
        self.packet_count += 1
        self.byte_count += pkt_size
        self.flow_end_ms = time.time() * 1000
        self.tcp_flags |= tcp_flags

        # 状态推进: 第二个报文到达 → ACTIVE
        if self.state == FlowState.NEW and self.packet_count >= 2:
            self.state = FlowState.ACTIVE

    @property
    def duration_sec(self) -> float:
        """流持续时间 (秒)"""
        return (self.flow_end_ms - self.flow_start_ms) / 1000.0

    def get_stats_dict(self) -> dict:
        """
        获取流统计摘要 (用于 IPFIX 导出和展现)
        """
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(self.key.protocol, str(self.key.protocol))
        return {
            "src_ip": self.key.src_ip,
            "dst_ip": self.key.dst_ip,
            "src_port": self.key.src_port,
            "dst_port": self.key.dst_port,
            "protocol": proto_name,
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "duration": self.duration_sec,
            "state": self.state.name,
        }