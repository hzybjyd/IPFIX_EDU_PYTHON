# ============================================================================
# protocol.py — IPFIX 协议编码 / 解码 (RFC 7011)
# ============================================================================
# IPFIX Message 结构:
#   ┌──────────────────────────────────────┐
#   │ Message Header (16 bytes)            │
#   │  - Version(2)  Length(2)             │
#   │  - Export Time(4) Sequence(4)        │
#   │  - Observation Domain ID(4)          │
#   ├──────────────────────────────────────┤
#   │ Set 1 (Template / Data)              │
#   │  - Set Header(4): ID + Length        │
#   │  - Records...                        │
#   ├──────────────────────────────────────┤
#   │ Set 2 ...                            │
#   └──────────────────────────────────────┘
#
# Template Record 定义 Information Element 的排列顺序;
# Data Record 是实际数据, 按 Template 的顺序填充值。

import struct
import time
from flow.record import FlowRecord
from config.settings import IPFIX


# ── IPFIX Information Element 定义 (PEN=0, IE 来自 IANA) ──
# 每个 IE: (ie_id, ie_length, name)
IE_SOURCE_IPV4      = (8,   4, "sourceIPv4Address")
IE_DEST_IPV4        = (12,  4, "destinationIPv4Address")
IE_SOURCE_PORT      = (7,   2, "sourceTransportPort")
IE_DEST_PORT        = (11,  2, "destinationTransportPort")
IE_PROTOCOL         = (4,   1, "protocolIdentifier")
IE_PACKET_COUNT     = (2,   8, "packetDeltaCount")
IE_BYTE_COUNT       = (1,   8, "octetDeltaCount")
IE_FLOW_START_MS    = (152, 8, "flowStartMilliseconds")
IE_FLOW_END_MS      = (153, 8, "flowEndMilliseconds")

# Template 中 IEs 的顺序 (决定了 Data Record 中字段的排列)
TEMPLATE_IES = [
    IE_SOURCE_IPV4,
    IE_DEST_IPV4,
    IE_SOURCE_PORT,
    IE_DEST_PORT,
    IE_PROTOCOL,
    IE_PACKET_COUNT,
    IE_BYTE_COUNT,
    IE_FLOW_START_MS,
    IE_FLOW_END_MS,
]


class IPFIXEncoder:
    """
    IPFIX 编码器
    ────────────
    将 FlowRecord 列表序列化为符合 RFC 7011 的二进制 IPFIX Message。

    使用方式:
        encoder = IPFIXEncoder()
        template_msg = encoder.build_template_message()
        data_msg     = encoder.build_data_message(flows)
        combined = encoder.build_combined_message(flows)  # 模板 + 数据
    """

    def __init__(self, observation_domain_id: int = 1, template_id: int = 256):
        self.observation_domain_id = observation_domain_id
        self.template_id = template_id
        self.sequence_number = 0  # 自增序列号

    def _build_header(self, total_length: int) -> bytes:
        """
        构建 IPFIX Message Header (16 bytes, RFC 7011 Section 3.1)
        """
        export_time = int(time.time())
        seq = self.sequence_number
        self.sequence_number += 1
        return struct.pack(
            "!HHIII",
            10,                        # Version Number (IPFIX = 10)
            total_length,              # Total Length
            export_time,               # Export Time (Unix seconds)
            seq,                       # Sequence Number
            self.observation_domain_id,# Observation Domain ID
        )

    def build_template_message(self) -> bytes:
        """
        构建 Template Set
        ─────────────────
        包含一个 Template Record, 定义所有 IEs 及其顺序。
        Collector 收到后即可按此格式解析后续 Data Record。
        """
        # Template Record: template_id + field_count + IEs
        field_count = len(TEMPLATE_IES)
        template_record = struct.pack("!HH", self.template_id, field_count)
        for ie_id, ie_len, _ in TEMPLATE_IES:
            # IE: ie_id(2) + ie_len(2) + enterprise(4, 0=IANA)
            template_record += struct.pack("!HHI", ie_id, ie_len, 0)

        # Set Header: set_id=2(Template), length
        set_header = struct.pack("!HH", 2, 4 + len(template_record))

        body = set_header + template_record
        header = self._build_header(16 + len(body))
        return header + body

    def build_data_message(self, flows: list[FlowRecord]) -> bytes:
        """
        构建 Data Set
        ─────────────
        将流列表编码为 Data Record, 字段顺序与 Template 定义一致。
        """
        if not flows:
            return b""

        # 逐个流编码为 Data Record
        records = b""
        for flow in flows:
            # IPv4 → 32-bit int
            src_ip_int = self._ip_to_int(flow.key.src_ip)
            dst_ip_int = self._ip_to_int(flow.key.dst_ip)
            # 构造 Data Record
            records += struct.pack(
                "!IIHHBQQQQ",
                src_ip_int,              # sourceIPv4Address (4)
                dst_ip_int,              # destinationIPv4Address (4)
                flow.key.src_port,       # sourceTransportPort (2)
                flow.key.dst_port,       # destinationTransportPort (2)
                flow.key.protocol,       # protocolIdentifier (1)
                flow.packet_count,       # packetDeltaCount (8)
                flow.byte_count,         # octetDeltaCount (8)
                int(flow.flow_start_ms), # flowStartMilliseconds (8)
                int(flow.flow_end_ms),   # flowEndMilliseconds (8)
            )

        # Set Header: set_id={template_id}, length
        set_header = struct.pack("!HH", self.template_id, 4 + len(records))

        body = set_header + records
        header = self._build_header(16 + len(body))
        return header + body

    def build_combined_message(self, flows: list[FlowRecord]) -> bytes:
        """
        构建 Template + Data 组合消息
        ───────────────────────────
        在同一 IPFIX Message 中包含 Template Set 和 Data Set,
        适合无状态的导出场景 (Collector 不需要预先接收模板)。
        """
        template_body = self.build_template_message()
        data_body = self.build_data_message(flows)

        # 去掉各自的 header, 共用一个 header
        template_payload = template_body[16:]  # 去 header
        data_payload = data_body[16:]

        combined_payload = template_payload + data_payload
        header = self._build_header(16 + len(combined_payload))
        return header + combined_payload

    @staticmethod
    def _ip_to_int(ip_str: str) -> int:
        """IPv4 字符串 → 32 位整数"""
        parts = ip_str.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | \
               (int(parts[2]) << 8)  | int(parts[3])


class IPFIXDecoder:
    """
    IPFIX 解码器 (用于 Collector)
    ────────────────────────────
    解析接收到的 IPFIX binary message:
    1. 解析 Message Header
    2. 解析 Template Set → 存储模板
    3. 解析 Data Set → 按模板解码流记录
    """
    def __init__(self):
        self._templates: dict[int, list[tuple[int, int]]] = {}  # template_id → [(ie_id, ie_len), ...]

    def parse_message(self, data: bytes) -> list[dict]:
        """解析 IPFIX 消息, 返回流记录列表"""
        if len(data) < 16:
            return []

        # 解析 Header
        version, total_len = struct.unpack_from("!HH", data, 0)
        if version != 10:
            return []

        offset = 16
        flows = []

        # 遍历 Sets
        while offset + 4 <= total_len:
            set_id, set_len = struct.unpack_from("!HH", data, offset)
            if set_len < 4 or offset + set_len > total_len:
                break

            set_data = data[offset + 4: offset + set_len]

            if set_id == 2:  # Template Set
                self._parse_template(set_data)
            elif set_id >= 256:  # Data Set (set_id == template_id)
                flows.extend(self._parse_data(set_id, set_data))

            offset += set_len

        return flows

    def _parse_template(self, data: bytes):
        """解析 Template Record"""
        offset = 0
        while offset + 4 <= len(data):
            template_id, field_count = struct.unpack_from("!HH", data, offset)
            offset += 4

            ies = []
            for _ in range(field_count):
                if offset + 8 > len(data):
                    break
                ie_id, ie_len, enterprise = struct.unpack_from("!HHI", data, offset)
                offset += 8
                if enterprise == 0:  # IANA
                    ies.append((ie_id, ie_len))

            if ies:
                self._templates[template_id] = ies

    def _parse_data(self, template_id: int, data: bytes) -> list[dict]:
        """按模板解析 Data Record"""
        ies = self._templates.get(template_id)
        if not ies:
            return []

        # 计算每条 record 的大小
        record_size = sum(ie_len for _, ie_len in ies)
        if record_size == 0:
            return []

        flows = []
        offset = 0
        # 按模板定义的 IEs 解析每条 record
        ie_format = {
            8:  "!I",  # sourceIPv4Address (4 bytes)
            12: "!I",  # destinationIPv4Address (4 bytes)
            7:  "!H",  # sourceTransportPort (2 bytes)
            11: "!H",  # destinationTransportPort (2 bytes)
            4:  "!B",  # protocolIdentifier (1 byte)
            2:  "!Q",  # packetDeltaCount (8 bytes)
            1:  "!Q",  # octetDeltaCount (8 bytes)
            152:"!Q",  # flowStartMilliseconds (8 bytes)
            153:"!Q",  # flowEndMilliseconds (8 bytes)
        }

        while offset + record_size <= len(data):
            record = {}
            pos = offset
            for ie_id, ie_len in ies:
                fmt = ie_format.get(ie_id)
                if not fmt:
                    pos += ie_len
                    continue
                value = struct.unpack_from(fmt, data, pos)[0]
                pos += ie_len

                # 字段映射
                if ie_id == 8:
                    record["src_ip"] = f"{(value>>24)&0xFF}.{(value>>16)&0xFF}.{(value>>8)&0xFF}.{value&0xFF}"
                elif ie_id == 12:
                    record["dst_ip"] = f"{(value>>24)&0xFF}.{(value>>16)&0xFF}.{(value>>8)&0xFF}.{value&0xFF}"
                elif ie_id == 7:
                    record["src_port"] = value
                elif ie_id == 11:
                    record["dst_port"] = value
                elif ie_id == 4:
                    record["protocol"] = value
                elif ie_id == 2:
                    record["packets"] = value
                elif ie_id == 1:
                    record["bytes"] = value
                elif ie_id == 152:
                    record["flow_start_ms"] = value
                elif ie_id == 153:
                    record["flow_end_ms"] = value

            flows.append(record)
            offset += record_size

        return flows