# ============================================================================
# rules.py — 阻断规则管理器
# ============================================================================
# 职责:
#   1. 维护阻断规则列表（增删改查）
#   2. 匹配数据包信息与规则
#   3. 构建 WinDivert filter 表达式
#
# 规则维度: IP (源/目的)、端口 (源/目的)、协议 (TCP/UDP/ICMP)

import threading
from typing import Optional


class RuleManager:
    """
    阻断规则管理器
    ──────────────
    每条规则为 dict:
      {
          "ip": str,         # IP 地址 (匹配源或目的, 空=不限)
          "src_port": int,   # 源端口 (0=不限)
          "dst_port": int,   # 目的端口 (0=不限)
          "protocol": str,   # "TCP"/"UDP"/"ICMP"/"" (空=不限)
          "enabled": bool,   # 是否启用
      }
    """

    def __init__(self, rules: Optional[list] = None):
        self._rules: list[dict] = []
        self._lock = threading.Lock()
        if rules:
            for r in rules:
                self._rules.append(self._normalize(r))

    @staticmethod
    def _normalize(rule: dict) -> dict:
        return {
            "ip": rule.get("ip", "").strip(),
            "src_port": int(rule.get("src_port", 0)),
            "dst_port": int(rule.get("dst_port", 0)),
            "protocol": rule.get("protocol", "").strip().upper(),
            "enabled": bool(rule.get("enabled", True)),
        }

    def add_rule(self, rule: dict) -> int:
        """添加规则, 返回规则索引"""
        with self._lock:
            self._rules.append(self._normalize(rule))
            return len(self._rules) - 1

    def remove_rule(self, index: int) -> bool:
        with self._lock:
            if 0 <= index < len(self._rules):
                self._rules.pop(index)
                return True
            return False

    def toggle_rule(self, index: int):
        """切换规则启用状态, 返回新状态; 索引无效返回 None"""
        with self._lock:
            if 0 <= index < len(self._rules):
                self._rules[index]["enabled"] = not self._rules[index]["enabled"]
                return self._rules[index]["enabled"]
            return None

    def update_rule(self, index: int, rule: dict) -> bool:
        with self._lock:
            if 0 <= index < len(self._rules):
                self._rules[index] = self._normalize(rule)
                return True
            return False

    def clear_rules(self):
        with self._lock:
            self._rules.clear()

    def get_all_rules(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._rules]

    def get_enabled_rules(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._rules if r["enabled"]]

    def __len__(self):
        with self._lock:
            return len(self._rules)

    # ─────────────────────────────────────────────────────────────
    #  规则匹配
    # ─────────────────────────────────────────────────────────────

    def match(self, pkt_info: dict) -> tuple[bool, int]:
        """
        检查报文信息是否命中任何启用的规则
        ─────────────────────────────────
        pkt_info: {"src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
        返回: (是否命中, 命中规则索引), 未命中返回 (False, -1)
        """
        with self._lock:
            for i, rule in enumerate(self._rules):
                if not rule["enabled"]:
                    continue
                if self._match_rule(rule, pkt_info):
                    return True, i
        return False, -1

    @staticmethod
    def _match_rule(rule: dict, pkt_info: dict) -> bool:
        proto_num = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(rule["protocol"], 0)

        # 协议匹配
        if proto_num and pkt_info["protocol"] != proto_num:
            return False

        # IP 匹配 (源或目的包含即命中)
        if rule["ip"]:
            if rule["ip"] not in (pkt_info["src_ip"], pkt_info["dst_ip"]):
                return False

        # 端口匹配 (仅 TCP/UDP)
        if rule["src_port"] and pkt_info["src_port"] != rule["src_port"]:
            return False
        if rule["dst_port"] and pkt_info["dst_port"] != rule["dst_port"]:
            return False

        return True

    # ─────────────────────────────────────────────────────────────
    #  WinDivert filter 表达式构建
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def build_filter_expr(rule: dict) -> str:
        """将单条规则转为 WinDivert filter 表达式"""
        parts = []
        proto = rule.get("protocol", "").upper()
        src_port = int(rule.get("src_port", 0))
        dst_port = int(rule.get("dst_port", 0))
        ip = rule.get("ip", "").strip()

        # 协议基础 filter
        if proto == "TCP":
            base = "tcp"
        elif proto == "UDP":
            base = "udp"
        elif proto == "ICMP":
            base = "icmp"
        else:
            base = ""

        # IP 条件
        ip_parts = []
        if ip:
            ip_parts.append(f"ip.SrcAddr == {ip}")
            ip_parts.append(f"ip.DstAddr == {ip}")

        # 端口条件 (TCP/UDP)
        port_parts = []
        if src_port:
            if proto == "TCP" or not proto:
                port_parts.append(f"tcp.SrcPort == {src_port}")
            if proto == "UDP" or not proto:
                port_parts.append(f"udp.SrcPort == {src_port}")
        if dst_port:
            if proto == "TCP" or not proto:
                port_parts.append(f"tcp.DstPort == {dst_port}")
            if proto == "UDP" or not proto:
                port_parts.append(f"udp.DstPort == {dst_port}")

        # 组合: 仅协议
        if base and not ip_parts and not port_parts:
            return base

        # 组合: 有 IP 或端口条件
        sub_parts = []
        if ip_parts:
            sub_parts.append(f"({' or '.join(ip_parts)})")
        if port_parts:
            sub_parts.append(f"({' or '.join(port_parts)})")

        combined = " and ".join(sub_parts)
        if base:
            combined = f"{base} and {combined}"
        return combined

    @classmethod
    def build_combined_filter(cls, rules: list[dict]) -> str:
        """将多条规则合并为一个 WinDivert filter 表达式"""
        enabled = [r for r in rules if r.get("enabled", True)]
        if not enabled:
            return "false"
        if len(enabled) == 1:
            return cls.build_filter_expr(enabled[0])
        parts = [cls.build_filter_expr(r) for r in enabled]
        return " or ".join(f"({p})" for p in parts)

    # ─────────────────────────────────────────────────────────────
    #  规则描述
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def describe_rule(rule: dict) -> str:
        """将规则描述为可读字符串"""
        parts = []
        if rule.get("protocol"):
            parts.append(rule["protocol"])
        if rule.get("ip"):
            parts.append(f"ip={rule['ip']}")
        if rule.get("src_port"):
            parts.append(f"src_port={rule['src_port']}")
        if rule.get("dst_port"):
            parts.append(f"dst_port={rule['dst_port']}")
        return " | ".join(parts) if parts else "(空规则)"
