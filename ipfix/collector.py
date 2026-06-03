# ============================================================================
# collector.py — IPFIX 收集器 (Collector)
# ============================================================================
# 在本地监听 UDP 端口, 接收 IPFIX Exporter 发送的流记录。
# 解析 Template Set 和 Data Set, 还原流信息并存储。
# 体现 IPFIX 协议的 "导出 → 收集" 完整闭环。

import socket
import threading
from ipfix.protocol import IPFIXDecoder
from config.settings import IPFIX, DEBUG


class IPFIXCollector:
    """
    IPFIX 收集器
    ────────────
    职责:
    1. 监听 UDP 端口, 接收 IPFIX 消息
    2. 解析消息头、模板和数据记录
    3. 存储解析后的流记录, 供展现模块使用
    """

    def __init__(self):
        self.decoder = IPFIXDecoder()
        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread = None

        # 收集统计
        self.messages_received = 0     # 收到的 IPFIX 消息数
        self.flows_received = 0        # 累计收到的流数
        self.bytes_received = 0        # 累计收到的字节数
        self.templates_received = 0    # 收到的模板数

        # 最近收到的流记录 (环形缓冲区, 用于展现)
        self.received_flows: list[dict] = []  # 最近 200 条
        self._flows_lock = threading.Lock()

    def start(self):
        """启动收集器 (绑定端口, 启动接收线程)"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((IPFIX["collector_host"], IPFIX["collector_port"]))
        self._sock.settimeout(1.0)  # 1 秒超时, 用于检查停止信号

        self._thread = threading.Thread(
            target=self._run, daemon=True, name="IPFIXCollector"
        )
        self._thread.start()
        print(f"[IPFIX收集] 监听 {IPFIX['collector_host']}:{IPFIX['collector_port']} [OK]")

    def stop(self):
        """停止收集器"""
        self._stop_event.set()
        if self._sock:
            self._sock.close()

    def _run(self):
        """
        收集器主循环
        ────────────
        持续接收 UDP 报文, 尝试解析为 IPFIX 消息。
        """
        buffer_size = 65535  # UDP 最大接收缓冲区

        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(buffer_size)
                self.bytes_received += len(data)
                self.messages_received += 1

                # 解析 IPFIX 消息
                try:
                    flows = self.decoder.parse_message(data)
                    if flows:
                        self.flows_received += len(flows)
                        with self._flows_lock:
                            for flow in flows:
                                self.received_flows.append(flow)
                                # 保持最近 200 条
                                if len(self.received_flows) > 200:
                                    self.received_flows.pop(0)
                except Exception as e:
                    if DEBUG.get("verbose"):
                        print(f"[IPFIX收集] 解析失败: {e}")
                    continue

            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

    def get_stats(self) -> dict:
        """获取收集器统计"""
        return {
            "messages_received": self.messages_received,
            "flows_received": self.flows_received,
            "bytes_received": self.bytes_received,
            "templates_received": self.templates_received,
        }

    def get_received_flows(self) -> list[dict]:
        """获取最近收到的流记录"""
        with self._flows_lock:
            return list(self.received_flows)
