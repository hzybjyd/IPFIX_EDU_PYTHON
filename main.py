# ============================================================================
# main.py — 基于 IPFIX 的流计量系统 主入口
# ============================================================================
# 系统启动流程:
#   1. 检测管理员权限 (抓包必须)
#   2. 检测 Python 依赖 (scapy/rich/psutil)
#   3. 启动各模块线程 (Collector → Capture → FlowMeter → Exporter → Display)
#   4. 主线程运行 Rich Live 控制台展现 + 快捷键交互
#   5. 退出时优雅停止所有线程
#
# 快捷键:
#   [Q] 退出    [1] 查看流详情    [2] 流统计    [3] 筛选配置

import sys
import os
import ctypes
import queue
import threading
import time

# 设置 stdout 为 UTF-8 编码 (Windows 控制台兼容)
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# 检测管理员权限 (必须最先执行)
def is_admin() -> bool:
    """检测当前进程是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not is_admin():
    print("=" * 60)
    print("  [!] " + ("需要管理员权限!"))
    print("  " + ("数据包捕获需要管理员权限。"))
    print("  " + ("请以管理员身份重新运行本程序:"))
    print("    1. 右键点击 PowerShell/CMD → '以管理员身份运行'")
    print("    " + ("2. 然后执行: python main.py"))
    print("=" * 60)
    # 尝试用 UAC 提权重启
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    except Exception:
        pass
    sys.exit(1)

# ── 导入依赖模块 (放在权限检查之后, 避免 import 时的副作用) ──
try:
    import msvcrt  # Windows 非阻塞键盘输入
except ImportError:
    msvcrt = None

from rich.live import Live
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout
from rich import box

from config.settings import CAPTURE, FLOW, IPFIX, DISPLAY, FILTER, DEBUG
from capture.sniffer import PacketCapture
from flow.record import FlowRecord, FlowState
from flow.meter import FlowTable, FlowMeter
from ipfix.protocol import IPFIXEncoder
from ipfix.exporter import IPFIXExporter
from ipfix.collector import IPFIXCollector

# ════════════════════════════════════════════════════════════════
#  全局状态
# ════════════════════════════════════════════════════════════════

running = True             # 主循环控制
console = Console()        # Rich 控制台

# ════════════════════════════════════════════════════════════════
#  流筛选函数
# ════════════════════════════════════════════════════════════════

def _has_filter_criteria(flt: dict) -> bool:
    """判断是否有有效筛选条件"""
    return bool(flt.get("ip") or flt.get("protocol") or flt.get("src_port") or flt.get("dst_port"))

def _describe_filter(flt: dict) -> str:
    """将筛选条件描述为可读字符串"""
    parts = []
    if flt.get("protocol"):
        parts.append(flt["protocol"].upper())
    if flt.get("ip"):
        parts.append(f"ip={flt['ip']}")
    if flt.get("src_port"):
        parts.append(f"src_port={flt['src_port']}")
    if flt.get("dst_port"):
        parts.append(f"dst_port={flt['dst_port']}")
    return " | ".join(parts) if parts else "无"

def _apply_flow_filter(flows: list, filter_config: dict) -> list:
    """
    对活跃流列表应用显示层筛选
    ──────────────────────────
    筛选条件全部为空/0 时不过滤, 否则精确匹配。
    IP:   源或目的 IP 含该字符串即匹配
    Port: 区分源端口和目的端口, 0=不筛选
    Protocol: 精确匹配传输层协议
    """
    cfg = filter_config["display"] if "display" in filter_config else filter_config
    if not _has_filter_criteria(cfg):
        return flows

    result = []
    for f in flows:
        if cfg.get("protocol"):
            proto_num = {"tcp": 6, "udp": 17, "icmp": 1}.get(cfg["protocol"].lower())
            if proto_num is None or f.key.protocol != proto_num:
                continue
        if cfg.get("ip"):
            if cfg["ip"] not in f.key.src_ip and cfg["ip"] not in f.key.dst_ip:
                continue
        if cfg.get("src_port"):
            if f.key.src_port != cfg["src_port"]:
                continue
        if cfg.get("dst_port"):
            if f.key.dst_port != cfg["dst_port"]:
                continue
        result.append(f)

    return result

# ════════════════════════════════════════════════════════════════
#  显示构建 (直接内联, 简化依赖)
# ════════════════════════════════════════════════════════════════

def build_display(packet_capture, flow_table, ipfix_exporter, ipfix_collector) -> Layout:
    """
    构建 Rich 布局: 标题栏 + 流表格 + 统计面板 + 快捷键栏
    """
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_column(
        Layout(_build_flow_table(flow_table), name="flows"),
        Layout(_build_stats(packet_capture, flow_table, ipfix_exporter, ipfix_collector), name="stats", size=9),
    )
    layout["header"].update(_build_header())
    layout["footer"].update(_build_footer())
    return layout

def _build_header() -> Panel:
    title = Text("IPFIX 流计量监控系统", style="bold cyan")
    sub = Text("RFC 7011 | Python + Scapy + Npcap | Windows", style="dim italic")

    # 筛选状态指示: 显示层 / BPF层
    flt_parts = []
    if _has_filter_criteria(FILTER["display"]):
        flt_parts.append(f"显示: {_describe_filter(FILTER['display'])}")
    if _has_filter_criteria(FILTER["bpf"]):
        flt_parts.append(f"BPF: {_describe_filter(FILTER['bpf'])}")
    if flt_parts:
        sub = Text.assemble(sub, "\n", ("  " + "  |  ".join(flt_parts), "bold yellow"))

    return Panel(Text.assemble(title, "\n", sub), style="cyan")

def _build_flow_table(flow_table) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold white", border_style="grey50", expand=True)
    table.add_column("源 IP", style="cyan", no_wrap=True, width=15)
    table.add_column("源端口", style="cyan", justify="right", width=6)
    table.add_column("目的 IP", style="magenta", no_wrap=True, width=15)
    table.add_column("目的端口", style="magenta", justify="right", width=6)
    table.add_column("协议", justify="center", width=5)
    table.add_column("报文", justify="right", width=6)
    table.add_column("字节", justify="right", width=9)
    table.add_column("时长", justify="right", width=5)
    table.add_column("状态", justify="center", width=7)

    active_flows = flow_table.get_active_flows()
    # 应用 Display 层筛选
    filtered_flows = _apply_flow_filter(active_flows, FILTER)
    filtered_flows.sort(key=lambda f: f.byte_count, reverse=True)
    max_show = DISPLAY.get("max_active_flows_show", 20)

    for flow in filtered_flows[:max_show]:
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.key.protocol, "?")
        proto_color = {"TCP": "green", "UDP": "blue", "ICMP": "yellow"}.get(proto, "white")
        state_color = {FlowState.NEW: "yellow", FlowState.ACTIVE: "green"}.get(flow.state, "white")
        byte_str = _fmt_bytes(flow.byte_count)

        table.add_row(
            flow.key.src_ip,
            str(flow.key.src_port) if flow.key.src_port else "-",
            flow.key.dst_ip,
            str(flow.key.dst_port) if flow.key.dst_port else "-",
            f"[{proto_color}]{proto}[/]",
            str(flow.packet_count),
            byte_str,
            f"{flow.duration_sec:.1f}s",
            f"[{state_color}]{flow.state.name}[/]",
        )

    if not active_flows:
        table.add_row("(等待中...)", "", "", "", "", "", "", "", "")

    # 标题: 有显示层筛选则显示筛选后/总数
    disp_active = _has_filter_criteria(FILTER["display"])
    if disp_active:
        title = f"[显示筛选] {len(filtered_flows)}/{len(active_flows)} 条流"
    else:
        title = f"活跃流 ({len(active_flows)})"
    return Panel(table, title=title, border_style="blue")

def _build_stats(packet_capture, flow_table, ipfix_exporter, ipfix_collector) -> Panel:
    stats = flow_table.get_stats()
    col_stats = ipfix_collector.get_stats()
    pc = packet_capture.packet_count
    active_total = stats['active_flows']
    disp_active = _has_filter_criteria(FILTER["display"])

    line1 = Text.assemble(
        ("报文: ", ""),
        (str(pc), "bold cyan"),
        ("  |  活跃: ", ""),
    )
    if disp_active:
        active_filtered = len(_apply_flow_filter(flow_table.get_active_flows(), FILTER))
        line1.append(f"{active_filtered}/{active_total}", "green")
    else:
        line1.append(str(active_total), "green")
    line1.append("  |  已创建: ", "")
    line1.append(str(stats['total_created']), "green")
    line1.append("  |  已过期: ", "")
    line1.append(str(stats['total_expired']), "yellow")
    line1.append("  |  已处理: ", "")
    line1.append(str(stats['total_packets']), "cyan")

    line2 = Text.assemble(
        ("导出: ", ""),
        (str(ipfix_exporter.export_count), "magenta"),
        (" 次  |  发送流: ", ""),
        (str(ipfix_exporter.total_flows_sent), "magenta"),
        ("  |  收集: ", ""),
        (str(col_stats['messages_received']), "blue"),
        (" 消息  |  接收流: ", ""),
        (str(col_stats['flows_received']), "blue"),
    )

    content = Text.assemble(line1, "\n", line2)

    # 筛选摘要行
    if disp_active or _has_filter_criteria(FILTER["bpf"]):
        parts = []
        if disp_active:
            parts.append(f"显示: {_describe_filter(FILTER['display'])}")
        if _has_filter_criteria(FILTER["bpf"]):
            parts.append(f"BPF: {_describe_filter(FILTER['bpf'])}")
        content.append("\n")
        content.append("  |  ".join(parts), "yellow")

    return Panel(content, title="统计", border_style="green")

def _build_footer() -> Panel:
    parts = [
        ("[Q]", "bold white"),
        ("退出", ""),
        ("  [1]", "bold white"),
        ("详情", ""),
        ("  [2]", "bold white"),
        ("统计", ""),
        ("  [3]", "bold white"),
        ("筛选", ""),
    ]
    tips = Text.assemble(*parts)
    return Panel(tips, style="grey50")

def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024**2:
        return f"{n/1024:.1f} KB"
    elif n < 1024**3:
        return f"{n/1024**2:.1f} MB"
    else:
        return f"{n/1024**3:.1f} GB"

# ════════════════════════════════════════════════════════════════
#  交互菜单处理
# ════════════════════════════════════════════════════════════════

def show_flow_details(flow_table):
    """暂停 Live 显示, 打印流详情 (应用显示层筛选)"""
    console.clear()
    console.print(Panel("流详情", style="bold cyan"))
    active = flow_table.get_active_flows()
    filtered = _apply_flow_filter(active, FILTER)
    filtered.sort(key=lambda f: f.byte_count, reverse=True)

    table = Table(box=box.ROUNDED, header_style="bold white")
    table.add_column("#", style="dim", width=4)
    for col in ["源 IP", "源端口", "目的 IP", "目的端口", "协议", "报文", "字节", "时长", "状态"]:
        table.add_column(col)

    for i, f in enumerate(filtered[:30], 1):
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(f.key.protocol, str(f.key.protocol))
        table.add_row(
            str(i), f.key.src_ip, str(f.key.src_port) if f.key.src_port else "-",
            f.key.dst_ip, str(f.key.dst_port) if f.key.dst_port else "-",
            proto, str(f.packet_count), _fmt_bytes(f.byte_count),
            f"{f.duration_sec:.1f}s", f.state.name
        )

    console.print(table)
    total_msg = f"总计: {len(active)} 条流"
    if _has_filter_criteria(FILTER["display"]):
        total_msg += f", 显示筛选: {len(filtered)} 条"
    console.print(total_msg, style="dim")
    input("\n按回车返回...")

def _input_filter_fields(flt: dict, title: str):
    """通用筛选字段输入"""
    console.clear()
    console.print(Panel(f"{title} — 筛选设置", style="bold yellow"))
    console.print(f"  当前: [yellow]{_describe_filter(flt)}[/]")
    console.print()
    console.print("  [1] 设置 IP")
    console.print("  [2] 设置协议 (TCP/UDP/ICMP)")
    console.print("  [3] 设置源端口")
    console.print("  [4] 设置目的端口")
    console.print("  [C] 清除此项筛选")
    console.print("  [X] 返回")

    choice = input("\n选择: ").strip().lower()

    if choice == '1':
        ip = input("IP (匹配源或目的, 回车=不限): ").strip()
        flt["ip"] = ip
        console.print(f"[green]IP: {flt['ip'] or '已清除'}[/]")
    elif choice == '2':
        proto = input("协议 (TCP/UDP/ICMP, 回车=不限): ").strip().upper()
        flt["protocol"] = proto if proto in ("TCP", "UDP", "ICMP") else ""
        console.print(f"[green]协议: {flt['protocol'] or '已清除'}[/]")
    elif choice == '3':
        try:
            port = int(input("源端口 (0=不限): ").strip())
            flt["src_port"] = port
        except ValueError:
            flt["src_port"] = 0
        console.print(f"[green]源端口: {flt['src_port'] or '已清除'}[/]")
    elif choice == '4':
        try:
            port = int(input("目的端口 (0=不限): ").strip())
            flt["dst_port"] = port
        except ValueError:
            flt["dst_port"] = 0
        console.print(f"[green]目的端口: {flt['dst_port'] or '已清除'}[/]")
    elif choice == 'c':
        flt["ip"] = ""
        flt["protocol"] = ""
        flt["src_port"] = 0
        flt["dst_port"] = 0
        console.print("[green]已清除[/]")

    input("\n按回车返回...")

def show_filter_menu(packet_capture):
    """
    筛选配置菜单
    ────────────
    根菜单 → 选择"显示层筛选"或"BPF层筛选"进入子菜单设置具体条件。
    筛选条件全部为空/0 即不筛选, 无需额外的开/关。
    """
    while True:
        console.clear()
        console.print(Panel("筛选配置", style="bold yellow"))

        ds = _describe_filter(FILTER["display"])
        bs = _describe_filter(FILTER["bpf"])
        console.print(f"  [1] 显示层筛选  — [yellow]{ds}[/]")
        console.print(f"  [2] BPF 捕获层筛选 — [yellow]{bs}[/]")
        console.print(f"  [3] 清除全部筛选")
        console.print(f"  [4] 以新 BPF 筛选重启捕获")
        console.print(f"  [X] 返回")

        choice = input("\n选择: ").strip().lower()

        if choice == '1':
            _input_filter_fields(FILTER["display"], "显示层筛选")
        elif choice == '2':
            _input_filter_fields(FILTER["bpf"], "BPF 捕获层筛选")
        elif choice == '3':
            for key in ("ip", "protocol", "src_port", "dst_port"):
                FILTER["display"][key] = "" if key in ("ip", "protocol") else 0
                FILTER["bpf"][key] = "" if key in ("ip", "protocol") else 0
            console.print("[green]已清除全部筛选[/]")
            input("\n按回车返回...")
        elif choice == '4':
            console.print("[yellow]正在以新的 BPF 筛选重启捕获...[/]")
            packet_capture.stop()
            time.sleep(0.5)
            packet_capture.start()
            console.print("[green]已按新 BPF 筛选重启捕获[/]")
            input("\n按回车返回...")
        elif choice == 'x':
            break

def handle_menu_key(key: str, packet_capture, flow_table, ipfix_exporter, ipfix_collector):
    """
    处理键盘快捷键
    ──────────────
    在 Live 上下文之外调用 (先 stop live, 处理, 再 start)
    """
    if key == '1':
        show_flow_details(flow_table)

    elif key == '2':
        console.clear()
        console.print(Panel("系统统计", style="bold cyan"))
        stats = flow_table.get_stats()
        console.print(f"  活跃流数:         {stats['active_flows']}")
        console.print(f"  流表总数:         {stats['total_flows']}")
        console.print(f"  累计创建:         {stats['total_created']}")
        console.print(f"  累计过期:         {stats['total_expired']}")
        console.print(f"  累计导出:         {stats['total_exported']}")
        console.print(f"  已处理报文:       {stats['total_packets']}")
        console.print(f"  已捕获报文:       {packet_capture.packet_count}")
        console.print(f"  导出次数:         {ipfix_exporter.export_count}")
        col_stats = ipfix_collector.get_stats()
        console.print(f"  收集器消息:       {col_stats['messages_received']}")
        console.print(f"  收集器流数:       {col_stats['flows_received']}")
        input("\n按回车返回...")

    elif key == '3':
        show_filter_menu(packet_capture)

# ════════════════════════════════════════════════════════════════
#  启动前筛选向导
# ════════════════════════════════════════════════════════════════

def _startup_filter_wizard():
    """
    启动前筛选向导
    ──────────────
    三个选项: 显示层筛选 / 捕获层筛选 / 不添加直接运行。
    选择前两项后进入具体配置, 配置完返回此菜单循环。
    选择"不添加"直接退出, 继续启动程序。
    """
    console.print()
    while True:
        console.print(Panel(
            "[bold yellow]启动筛选设置[/]\n"
            "选择筛选层级后配置具体条件, 或直接运行。",
            border_style="yellow"
        ))
        console.print(f"  [1] 显示层筛选 (控制台展现过滤)  — [yellow]{_describe_filter(FILTER['display'])}[/]")
        console.print(f"  [2] 捕获层筛选 (BPF 抓包过滤)   — [yellow]{_describe_filter(FILTER['bpf'])}[/]")
        console.print("  [3] 不添加, 直接运行")
        console.print()

        choice = input("选择: ").strip()

        if choice == '1':
            _input_filter_fields(FILTER["display"], "显示层筛选")
        elif choice == '2':
            _input_filter_fields(FILTER["bpf"], "BPF 捕获层筛选")
        elif choice == '3':
            break
        else:
            continue

    # 汇总
    if _has_filter_criteria(FILTER["display"]) or _has_filter_criteria(FILTER["bpf"]):
        console.print()
        if _has_filter_criteria(FILTER["display"]):
            console.print(f"  [cyan]显示: {_describe_filter(FILTER['display'])}[/]")
        if _has_filter_criteria(FILTER["bpf"]):
            console.print(f"  [yellow]BPF:  {_describe_filter(FILTER['bpf'])}[/]")
    else:
        console.print("\n[dim]未设置筛选条件, 将捕获全部流量[/]")

    console.print()
    time.sleep(1)

# ════════════════════════════════════════════════════════════════
#  主入口
# ════════════════════════════════════════════════════════════════

def main():
    global running

    # ── 启动 Banner ──
    console.clear()
    console.print()
    console.print(Panel(
        "[bold cyan]IPFIX 流计量系统[/]\n"
        "[dim]基于 RFC 7011 | Python + Scapy + Npcap[/]\n\n"
        "功能:\n"
        "  • 数据包捕获与流计量 (5-tuple 哈希)\n"
        "  • IPFIX 协议编码与导出 (UDP + 文件)\n"
        "  • IPFIX 收集器 (导出-收集闭环验证)\n"
        "  • Rich 控制台实时展现",
        title="🚀 系统初始化",
        border_style="cyan"
    ))

    # ── 检查依赖 ──
    console.print("[检查] 验证 Python 依赖...", style="yellow")
    missing = []
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    try:
        import rich
    except ImportError:
        missing.append("rich")
    try:
        import psutil
    except ImportError:
        missing.append("psutil")

    if missing:
        console.print(f"[错误] 缺少依赖: {', '.join(missing)}", style="bold red")
        console.print(f"请运行: pip install {' '.join(missing)}", style="yellow")
        console.print("或: pip install -r requirements.txt", style="yellow")
        sys.exit(1)
    console.print("[" + ("检查") + "] " + ("依赖就绪") + " [OK]", style="green")

    # ── 初始化所有组件 ──
    console.print("[" + ("初始化") + "] " + ("创建模块实例..."), style="yellow")

    # 共享队列 (捕获 → 流计量)
    packet_queue = queue.Queue(maxsize=10000)

    # 各模块
    capture = PacketCapture(packet_queue)
    flow_table = FlowTable()
    flow_meter = FlowMeter(packet_queue, flow_table)
    ipfix_exporter = IPFIXExporter(flow_table)
    ipfix_collector = IPFIXCollector()

    console.print("[" + ("初始化") + "] " + ("模块就绪") + " [OK]", style="green")

    # ── 启动前: 筛选条件预设 ──
    _startup_filter_wizard()

    # ── 启动线程 (按依赖顺序) ──
    console.print("[" + ("启动") + "] " + ("开启各模块线程..."), style="yellow")

    ipfix_collector.start()       # 1. 先启动收集器 (等待导出)
    capture.start()               # 2. 启动抓包 (开始生产报文)
    flow_meter.start()            # 3. 启动流计量 (消费报文)
    ipfix_exporter.start()        # 4. 启动导出器 (定时导出过期流)

    console.print("[" + ("启动") + "] " + ("所有模块已启动") + " [OK]", style="green")
    console.print()
    console.print("[" + ("提示") + "] 按 [bold]Q[/] 退出, 数字键操作菜单", style="dim")
    time.sleep(2)

    # ── 主循环: Rich Live 显示 + 键盘交互 ──
    try:
        with Live(
            build_display(capture, flow_table, ipfix_exporter, ipfix_collector),
            console=console,
            screen=True,
            refresh_per_second=4,
            transient=False,
        ) as live:
            while running:
                # 更新显示
                live.update(
                    build_display(capture, flow_table, ipfix_exporter, ipfix_collector)
                )

                # 检查键盘输入 (Windows)
                if msvcrt and msvcrt.kbhit():
                    ch = msvcrt.getch().decode('utf-8', errors='ignore').lower()

                    if ch in ('q', '0'):
                        running = False
                        break

                    if ch in ('1', '2', '3'):
                        live.stop()  # 暂停 Live 显示
                        try:
                            handle_menu_key(
                                ch, capture, flow_table,
                                ipfix_exporter, ipfix_collector
                            )
                        except Exception as e:
                            console.print("[" + ("错误") + f"] {e}", style="red")
                            input(("按回车继续..."))
                        live.start()  # 恢复 Live 显示

                # 非 Windows 或无 msvcrt 的回退 (阻塞输入)
                elif msvcrt is None:
                    try:
                        ch = input().strip().lower()
                        if ch in ('q', '0'):
                            running = False
                            break
                        if ch in ('1', '2', '3'):
                            live.stop()
                            try:
                                handle_menu_key(
                                    ch, capture, flow_table,
                                    ipfix_exporter, ipfix_collector
                                )
                            except Exception as e:
                                console.print("[" + ("错误") + f"] {e}", style="red")
                                input(("按回车继续..."))
                            live.start()
                    except EOFError:
                        pass

                time.sleep(0.1)

    except KeyboardInterrupt:
        console.print("\n[" + ("系统") + "] " + ("收到中断信号, 正在退出..."), style="yellow")
        running = False

    # ── 优雅关闭 ──
    console.print("\n[" + ("关闭") + "] " + ("正在停止所有模块..."), style="yellow")

    capture.stop()
    flow_meter.stop()
    ipfix_exporter.stop()
    ipfix_collector.stop()

    console.print("[" + ("关闭") + "] " + ("系统已安全退出") + " [OK]", style="bold green")
    console.print("\n  " + ("会话统计:"))
    console.print(f"    " + ("捕获报文:") + "   {capture.packet_count}")
    console.print(f"    " + ("创建流:") + "     {flow_table.total_flows_created}")
    console.print(f"    " + ("导出流:") + "     {flow_table.total_flows_exported}")
    console.print(f"    " + ("导出次数:") + "   {ipfix_exporter.export_count}")
    console.print(f"    " + ("收集消息:") + "   {ipfix_collector.messages_received}")

if __name__ == "__main__":
    main()