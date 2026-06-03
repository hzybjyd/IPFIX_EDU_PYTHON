# ============================================================================
# meter.py — 流计量引擎 (Flow Metering Process)
# ============================================================================
# 核心功能:
#   1. 从报文队列中消费原始报文
#   2. 提取 5-tuple 建立/更新流记录
#   3. 周期性检查并标记过期流
#   4. 返回待导出的已过期流列表
#
# 这是 IPFIX 架构中的 Metering Process, 负责将报文聚合为流。

import queue
import threading
import time
from scapy.all import IP, TCP, UDP, ICMP
from flow.record import FlowKey, FlowRecord, FlowState
from config.settings import FLOW, DEBUG


class FlowTable:
    """
    流表 (Flow Cache)
    ─────────────────
    基于哈希表的流存储, 以 FlowKey (5-tuple) 为键快速查找流记录。

    内部结构:
        _flows:  dict[FlowKey, FlowRecord]  活跃流 + 待导出过期流
        _lock:   threading.Lock             保证多线程安全
    """

    def __init__(self):
        self._flows: dict[FlowKey, FlowRecord] = {}
        self._lock = threading.Lock()
        self.total_flows_created = 0    # 累计建立的流总数
        self.total_flows_expired = 0    # 累计过期的流总数
        self.total_flows_exported = 0   # 累计导出的流总数
        self.total_packets_processed = 0  # 累计处理的报文数

    # ─────────────────────────────────────────────────────────────
    #  流表基本操作
    # ─────────────────────────────────────────────────────────────

    def get(self, key: FlowKey) -> FlowRecord | None:
        """根据 5-tuple 查找流记录 (线程安全)"""
        with self._lock:
            return self._flows.get(key)

    def get_or_create(self, key: FlowKey) -> FlowRecord:
        """
        查找或创建流记录
        ────────────────
        若流已存在则返回, 否则创建新流并加入流表。
        新流状态为 NEW, 收到第二个报文时自动转为 ACTIVE。
        """
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                # 流表容量保护
                if len(self._flows) >= FLOW["max_flows"]:
                    self._evict_oldest()
                flow = FlowRecord(key=key)
                self._flows[key] = flow
                self.total_flows_created += 1
                if DEBUG.get("verbose"):
                    print(f"[FlowTable] 新建流: {key} (总数: {len(self._flows)})")
            return flow

    def update_flow(self, key: FlowKey, pkt_size: int, tcp_flags: int = 0):
        """
        更新流记录 (线程安全)
        ───────────────────
        查找或创建流, 累加报文数和字节数。
        """
        flow = self.get_or_create(key)
        with self._lock:
            flow.update(pkt_size, tcp_flags)
        self.total_packets_processed += 1

    def _evict_oldest(self):
        """淘汰最旧的流 (流表满时调用)"""
        if not self._flows:
            return
        oldest = min(self._flows.values(), key=lambda f: f.flow_start_ms)
        del self._flows[oldest.key]

    # ─────────────────────────────────────────────────────────────
    #  流过期检查
    # ─────────────────────────────────────────────────────────────

    def check_expired_flows(self):
        """
        遍历流表, 标记过期流
        ──────────────────
        过期条件 (任一满足):
        1. 空闲超时: 距最后活跃时间超过 idle_timeout 秒
        2. 活跃超时: 距流创建时间超过 active_timeout 秒
        3. TCP 结束: 收到 FIN 或 RST 标志
        """
        now = time.time()
        idle_timeout = FLOW["idle_timeout"]
        active_timeout = FLOW["active_timeout"]
        tcp_fin = FLOW.get("tcp_timeout_on_fin", True)
        tcp_rst = FLOW.get("tcp_timeout_on_rst", True)

        with self._lock:
            expired = []
            for key, flow in self._flows.items():
                if flow.state in (FlowState.EXPORTED, FlowState.EXPIRED):
                    continue

                flow_end_sec = flow.flow_end_ms / 1000.0

                # 条件1: 空闲超时
                if now - flow_end_sec >= idle_timeout:
                    flow.state = FlowState.EXPIRED
                    expired.append(key)

                # 条件2: 活跃超时
                elif now - flow.flow_start_ms / 1000.0 >= active_timeout:
                    flow.state = FlowState.EXPIRED
                    expired.append(key)

                # 条件3: TCP FIN/RST
                elif flow.key.protocol == 6:  # TCP
                    if tcp_fin and (flow.tcp_flags & 0x01):  # FIN
                        flow.state = FlowState.EXPIRED
                        expired.append(key)
                    elif tcp_rst and (flow.tcp_flags & 0x04):  # RST
                        flow.state = FlowState.EXPIRED
                        expired.append(key)

            self.total_flows_expired += len(expired)
            if DEBUG.get("verbose") and expired:
                print(f"[FlowTable] 过期流: {len(expired)} 条 (总数: {self.total_flows_expired})")

    def get_expired_unexported(self) -> list[FlowRecord]:
        """
        取出已过期且未导出的流 (从流表移除)
        ────────────────────────────────
        调用后将流的 EXPIRE 状态标记为 EXPORTED, 从流表移除并返回。
        """
        with self._lock:
            expired = []
            to_remove = []
            for key, flow in self._flows.items():
                if flow.state == FlowState.EXPIRED and flow.state != FlowState.EXPORTED:
                    flow.state = FlowState.EXPORTED
                    expired.append(flow)
                    to_remove.append(key)
                    self.total_flows_exported += 1

            for key in to_remove:
                del self._flows[key]

            return expired

    # ─────────────────────────────────────────────────────────────
    #  查询接口
    # ─────────────────────────────────────────────────────────────

    def get_active_flows(self) -> list[FlowRecord]:
        """获取所有活跃流 (NEW + ACTIVE)"""
        with self._lock:
            return [f for f in self._flows.values()
                    if f.state in (FlowState.NEW, FlowState.ACTIVE)]

    def get_all_flows(self) -> list[FlowRecord]:
        """获取流表中所有流"""
        with self._lock:
            return list(self._flows.values())

    def get_stats(self) -> dict:
        """获取流表统计信息"""
        with self._lock:
            active = sum(1 for f in self._flows.values()
                        if f.state in (FlowState.NEW, FlowState.ACTIVE))
            return {
                "active_flows": active,
                "total_flows": len(self._flows),
                "total_created": self.total_flows_created,
                "total_expired": self.total_flows_expired,
                "total_exported": self.total_flows_exported,
                "total_packets": self.total_packets_processed,
            }


class FlowMeter:
    """
    流计量引擎
    ──────────
    从报文队列中消费原始报文, 提取 5-tuple, 更新流表。
    在独立线程中运行, 作为消费者。

    职责:
    1. 从共享队列获取原始报文
    2. 解析 IP/TCP/UDP/ICMP 头部
    3. 构建 FlowKey (5-tuple)
    4. 调用 FlowTable.update_flow() 更新统计
    """

    def __init__(self, packet_queue: queue.Queue, flow_table: FlowTable):
        self.packet_queue = packet_queue
        self.flow_table = flow_table
        self._stop_event = threading.Event()
        self._thread = None
        self.processed_count = 0

    def start(self):
        """启动流计量线程"""
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="FlowMeter"
        )
        self._thread.start()

    def stop(self):
        """停止流计量线程"""
        self._stop_event.set()

    def _run(self):
        """
        流计量主循环
        ────────────
        持续从队列获取报文, 解析后更新流表。
        通过 _stop_event 和队列超时 (1秒) 实现优雅停止。
        """
        while not self._stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                self._process_packet(pkt)
            except Exception as e:
                if DEBUG.get("verbose"):
                    print(f"[FlowMeter] 处理报文异常: {e}")
                continue

        # 停止前处理队列中剩余的报文
        while not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                self._process_packet(pkt)
            except queue.Empty:
                break
            except Exception:
                continue

    def _process_packet(self, pkt):
        """
        处理单个报文 → 提取 5-tuple → 更新流表
        ──────────────────────────────────────
        """
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        pkt_size = ip.len

        src_port = 0
        dst_port = 0
        tcp_flags = 0

        # 提取传输层信息
        if protocol == 6 and pkt.haslayer(TCP):  # TCP
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = tcp.flags & 0xFF  # 只取低 8 位
        elif protocol == 17 and pkt.haslayer(UDP):  # UDP
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
        elif protocol == 1 and pkt.haslayer(ICMP):  # ICMP
            # ICMP 无端口, src_port/dst_port 保持为 0
            pass

        # 构建 5-tuple 并更新流表
        key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        self.flow_table.update_flow(key, pkt_size, tcp_flags)
        self.processed_count += 1
