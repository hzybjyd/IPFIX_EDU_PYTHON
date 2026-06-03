# ============================================================================
# exporter.py — IPFIX 导出器 (Exporter)
# ============================================================================
# 职责:
#   1. 启动时创建本次运行的专属导出目录
#   2. 发送 Template Message (告知 Collector 数据格式)
#   3. 周期性从流表中取出已过期流, 编码为 IPFIX Data Message 并发送
#   4. 将每次导出的数据写入 .ipfix 文件

import socket
import os
import time
import threading
from datetime import datetime
from ipfix.protocol import IPFIXEncoder
from flow.record import FlowRecord
from config.settings import IPFIX, DEBUG


class IPFIXExporter:
    """
    IPFIX 导出器
    ────────────
    职责:
    1. 启动时创建本次运行的专属导出目录
    2. 发送 Template Message (告知 Collector 数据格式)
    3. 周期性从流表中取出已过期流, 编码为 IPFIX Data Message 并发送
    4. 将每次导出的数据写入 .ipfix 文件
    """

    def __init__(self, flow_table):
        self.flow_table = flow_table
        self.encoder = IPFIXEncoder(
            observation_domain_id=IPFIX["observation_domain_id"],
            template_id=IPFIX["template_id"],
        )
        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread = None
        self.export_count = 0
        self.total_flows_sent = 0
        self._export_dir = None  # 本次运行的导出目录, start() 时创建

        # 文件导出基础目录
        self._export_file_enabled = IPFIX.get("export_file_enabled", False)
        self._export_base_dir = IPFIX.get("export_file_dir", "./ipfix_data")

    def start(self):
        """启动导出器 (创建导出目录, 发送模板, 启动导出线程)"""
        # 创建本次运行的专属目录: ./ipfix_data/20260603_143052/
        if self._export_file_enabled:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self._export_dir = os.path.join(self._export_base_dir, timestamp)
            os.makedirs(self._export_dir, exist_ok=True)
            print(f"[IPFIX导出] 导出目录: {self._export_dir}")

        self._create_socket()
        self._send_template()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="IPFIXExporter"
        )
        self._thread.start()
        print(f"[IPFIX导出] 已启动, 导出到 {IPFIX['collector_host']}:{IPFIX['collector_port']} [OK]")

    def stop(self):
        """停止导出器"""
        self._stop_event.set()
        if self._sock:
            self._sock.close()
        if self._export_dir:
            print(f"[IPFIX导出] 本次导出文件保存在: {self._export_dir}")

    # ─────────────────────────────────────────────────────────────
    #  内部实现
    # ─────────────────────────────────────────────────────────────

    def _create_socket(self):
        """创建 UDP socket"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def _send_template(self):
        """发送 Template Message 到 Collector（仅 UDP，不写文件）"""
        message = self.encoder.build_template_message()
        self._send_udp(message)

    def _send_udp(self, message: bytes):
        """通过 UDP 发送 IPFIX 消息"""
        try:
            self._sock.sendto(
                message,
                (IPFIX["collector_host"], IPFIX["collector_port"])
            )
        except Exception as e:
            if DEBUG.get("verbose"):
                print(f"[IPFIX导出] UDP 发送失败: {e}")

    def _write_to_file(self, message: bytes):
        """
        将 IPFIX 二进制消息写入文件
        ──────────────────────────
        写入到本次运行专属目录下, 文件名以时间戳+序号命名。
        可用 Wireshark 直接打开验证 IPFIX 格式是否正确。
        """
        if not self._export_dir:
            return
        filename = os.path.join(
            self._export_dir,
            f"ipfix_export_{int(time.time())}_{self.export_count:04d}.ipfix"
        )
        try:
            with open(filename, "wb") as f:
                f.write(message)
        except Exception as e:
            print(f"[IPFIX导出] 文件写入失败: {e}")

    def _export_flows(self, flows: list[FlowRecord]):
        """将流列表编码并导出"""
        if not flows:
            return

        # 使用组合消息 (模板 + 数据), 便于无状态 Collector 解析
        message = self.encoder.build_combined_message(flows)
        self._send_udp(message)
        self._write_to_file(message)

        self.total_flows_sent += len(flows)
        self.export_count += 1

        if DEBUG.get("verbose"):
            print(f"[IPFIX导出] 第 {self.export_count} 次导出: "
                  f"{len(flows)} 条流, {len(message)} bytes")

    def _run(self):
        """
        导出器主循环
        ────────────
        每隔 export_interval 秒执行一次导出:
        1. 检查流表中过期流
        2. 取出已过期未导出的流
        3. 编码并发送
        """
        template_resend_sec = IPFIX.get("template_resend_interval", 10) * IPFIX["export_interval"]
        last_template_time = time.time()  # 首次模板已在 start() 中发送

        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=IPFIX["export_interval"])
            if self._stop_event.is_set():
                break

            try:
                # 检查过期流
                self.flow_table.check_expired_flows()

                # 取出已过期未导出的流
                expired_flows = self.flow_table.get_expired_unexported()

                if expired_flows:
                    self._export_flows(expired_flows)
                elif DEBUG.get("verbose"):
                    print(f"[IPFIX导出] 无过期流 (活跃: {self.flow_table.get_stats()['active_flows']})")

                # 周期性重发模板 (确保新加入的 Collector 能解析数据)
                elapsed = time.time() - last_template_time
                if elapsed >= template_resend_sec:
                    self._send_template()
                    last_template_time = time.time()

            except Exception as e:
                print(f"[IPFIX导出] 导出异常: {e}")

        # 停止前: 最后一次导出所有剩余流
        try:
            self.flow_table.check_expired_flows()
            remaining = self.flow_table.get_expired_unexported()
            if remaining:
                self._export_flows(remaining)
        except Exception:
            pass
