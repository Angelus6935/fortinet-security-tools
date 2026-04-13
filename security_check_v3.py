"""
╔══════════════════════════════════════════════════════════════════╗
║         SECURITY DIAGNOSTIC TOOL - Windows 11                   ║
║         Basado en: Fortinet NSE1 - Threat Landscape 3.0         ║
║         Detecta: Malware, Backdoors, C2, Spyware indicators     ║
║         Autor: Jose Angel Aponte - Network Automation Engineer   ║
║         GitHub: github.com/Angelus6935                           ║
╚══════════════════════════════════════════════════════════════════╝

DISCLAIMER:
    Esta herramienta es de uso EDUCATIVO y DEFENSIVO.
    Basada en conceptos del curso Fortinet NSE1 Threat Landscape 3.0.
    Solo LEE información del sistema — no modifica, no elimina,
    no realiza conexiones externas.
    No reemplaza un antivirus profesional (ej: FortiClient).
    Úsala solo en sistemas de tu propiedad o con autorización explícita.

Instalación requerida:
    pip install psutil colorama

Uso:
    python security_check.py

Ejecutar como Administrador para resultados completos.
"""

import os
import sys
import socket
import hashlib
import datetime
import subprocess
import json

try:
    import psutil
    import colorama
    from colorama import Fore, Style, Back
    colorama.init()
except ImportError:
    print("[!] Instalando dependencias...")
    subprocess.run([sys.executable, "-m", "pip", "install", "psutil", "colorama"], check=True)
    import psutil
    import colorama
    from colorama import Fore, Style, Back
    colorama.init()

# ─────────────────────────────────────────────
# CONFIGURACIÓN — IOCs y patrones conocidos
# ─────────────────────────────────────────────

# Puertos usados frecuentemente por C2/malware/backdoors
SUSPICIOUS_PORTS = {
    1337: "Leet/Backdoor clásico",
    4444: "Metasploit default",
    5555: "Android ADB / RAT",
    6666: "IRC Botnet C2",
    6667: "IRC Botnet C2",
    7777: "Backdoor genérico",
    8080: "Proxy/C2 alternativo",
    8443: "HTTPS alternativo sospechoso",
    9001: "Tor relay",
    9050: "Tor SOCKS proxy",
    31337: "Back Orifice backdoor",
    12345: "NetBus backdoor",
    54321: "Backdoor reverso",
}

# Procesos conocidos como maliciosos o sospechosos
SUSPICIOUS_PROCESSES = [
    "netcat", "nc.exe", "ncat",
    "mimikatz", "mimi",
    "pwdump", "fgdump",
    "psexec",
    "meterpreter",
    "empire",
    "cobalt",
    "cobaltstrike",
    "beacon",
    "njrat", "darkcomet", "nanocore",
    "remcos", "asyncrat",
]

# Procesos legítimos que suelen ser suplantados (masquerading)
LEGIT_PROCESS_NAMES = [
    "svchost.exe", "explorer.exe", "winlogon.exe",
    "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "wininit.exe", "taskhost.exe",
]

# Procesos legítimos que pueden usar puertos dinámicos — no alertar
WHITELISTED_DYNAMIC_PORT_PROCS = [
    "svchost.exe", "wininit.exe", "lsass.exe", "services.exe",
    "spoolsv.exe", "steam.exe", "code.exe", "msedge.exe",
    "chrome.exe", "firefox.exe", "teams.exe", "onedrive.exe",
    "discord.exe", "spotify.exe", "zoom.exe", "skype.exe",
    "system", "system idle process",
]

# Directorios sospechosos de ejecución de malware
SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\public\\",
    "\\recycle", "\\$recycle",
    "\\programdata\\",
]

# ─────────────────────────────────────────────
# UTILIDADES DE OUTPUT
# ─────────────────────────────────────────────

findings = []

def header(title):
    print(f"\n{Fore.CYAN}{'═'*65}")
    print(f"  {title}")
    print(f"{'═'*65}{Style.RESET_ALL}")

def ok(msg):
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {msg}")

def warn(msg):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    findings.append(("ADVERTENCIA", msg))

def alert(msg):
    print(f"  {Fore.RED}[⚠]{Style.RESET_ALL} {Fore.RED}{msg}{Style.RESET_ALL}")
    findings.append(("ALERTA", msg))

def info(msg):
    print(f"  {Fore.BLUE}[i]{Style.RESET_ALL} {msg}")

# ─────────────────────────────────────────────
# MÓDULO 1: PROCESOS SOSPECHOSOS
# Detecta: Malware, RATs, Backdoors, Keyloggers
# ─────────────────────────────────────────────

def check_processes():
    header("MÓDULO 1 — Procesos Sospechosos (Malware/Backdoor/RAT)")
    found_suspicious = False

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cmdline']):
        try:
            pname = proc.info['name'].lower() if proc.info['name'] else ""
            pexe  = proc.info['exe'].lower()  if proc.info['exe']  else ""
            pcmd  = " ".join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""

            # Verificar procesos conocidos como maliciosos
            for suspicious in SUSPICIOUS_PROCESSES:
                if suspicious in pname or suspicious in pexe:
                    alert(f"Proceso malicioso detectado: {proc.info['name']} (PID:{proc.info['pid']})")
                    found_suspicious = True

            # Verificar procesos legítimos ejecutados desde paths sospechosos
            if any(lp in pname for lp in LEGIT_PROCESS_NAMES):
                for sp in SUSPICIOUS_PATHS:
                    if sp in pexe:
                        alert(f"Proceso legítimo suplantado desde path sospechoso:")
                        alert(f"  → {proc.info['name']} ejecutando desde: {pexe}")
                        found_suspicious = True

            # Detectar PowerShell codificado (técnica común de malware)
            if "powershell" in pname and ("-enc" in pcmd or "-encodedcommand" in pcmd):
                alert(f"PowerShell con comando codificado (posible malware):")
                alert(f"  → PID: {proc.info['pid']}")
                found_suspicious = True

            # Detectar procesos sin ejecutable conocido (malware fileless)
            if proc.info['name'] and not proc.info['exe']:
                if proc.info['name'].lower() not in ["system", "registry", "memory compression",
                                                      "system idle process", "secure system"]:
                    warn(f"Proceso sin ejecutable conocido: {proc.info['name']} (PID:{proc.info['pid']})")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not found_suspicious:
        ok("No se detectaron procesos maliciosos conocidos")

# ─────────────────────────────────────────────
# MÓDULO 2: CONEXIONES DE RED SOSPECHOSAS
# Detecta: C2, Backdoors, Botnets, Spyware
# ─────────────────────────────────────────────

def check_network():
    header("MÓDULO 2 — Conexiones de Red Sospechosas (C2/Botnet/Spyware)")
    found_suspicious = False

    connections = psutil.net_connections(kind='inet')

    for conn in connections:
        try:
            laddr = conn.laddr
            raddr = conn.raddr if conn.raddr else None
            status = conn.status
            pid = conn.pid

            # Verificar puertos sospechosos locales
            if laddr and laddr.port in SUSPICIOUS_PORTS:
                alert(f"Puerto sospechoso ABIERTO localmente: {laddr.port} "
                      f"→ {SUSPICIOUS_PORTS[laddr.port]} (PID:{pid})")
                found_suspicious = True

            # Verificar conexiones a puertos sospechosos remotos
            if raddr and raddr.port in SUSPICIOUS_PORTS:
                alert(f"Conexión a puerto sospechoso REMOTO: {raddr.ip}:{raddr.port} "
                      f"→ {SUSPICIOUS_PORTS[raddr.port]} (PID:{pid})")
                found_suspicious = True

            # Detectar múltiples conexiones ESTABLISHED desde el mismo proceso
            # (posible participación en botnet/DDoS)

        except Exception:
            continue

    # Contar conexiones por proceso para detectar comportamiento botnet
    conn_count = {}
    for conn in connections:
        if conn.pid and conn.status == 'ESTABLISHED':
            conn_count[conn.pid] = conn_count.get(conn.pid, 0) + 1

    for pid, count in conn_count.items():
        if count > 20:
            try:
                proc = psutil.Process(pid)
                # Ignorar navegadores y apps conocidas con muchas conexiones
                if proc.name().lower() in WHITELISTED_DYNAMIC_PORT_PROCS:
                    continue
                alert(f"Proceso con {count} conexiones activas (posible botnet/DDoS):")
                alert(f"  → {proc.name()} (PID:{pid})")
                found_suspicious = True
            except psutil.NoSuchProcess:
                continue

    # Verificar puertos en escucha no habituales
    info("Puertos en escucha (LISTEN):")
    listening = [c for c in connections if c.status == 'LISTEN']
    for conn in listening:
        if conn.laddr:
            port = conn.laddr.port
            pid  = conn.pid
            try:
                pname = psutil.Process(pid).name() if pid else "Desconocido"
            except:
                pname = "Desconocido"
            if port in SUSPICIOUS_PORTS:
                alert(f"  Puerto {port} en escucha → {SUSPICIOUS_PORTS[port]} | Proceso: {pname}")
                found_suspicious = True
            elif port > 49151:
                if pname.lower() not in WHITELISTED_DYNAMIC_PORT_PROCS:
                    warn(f"  Puerto dinámico/privado en escucha: {port} | Proceso: {pname}")

    if not found_suspicious:
        ok("No se detectaron conexiones de red sospechosas")

# ─────────────────────────────────────────────
# MÓDULO 3: CAMBIOS EN ARCHIVOS DEL SISTEMA
# Detecta: Rootkits, Virus, Ransomware
# ─────────────────────────────────────────────

def check_startup():
    header("MÓDULO 3 — Entradas de Inicio Sospechosas (Persistencia/Rootkit)")
    found_suspicious = False

    # Verificar registro de inicio via WMIC
    try:
        result = subprocess.run(
            ["wmic", "startup", "get", "Caption,Command,Location"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split('\n')
        info("Entradas de inicio del sistema:")
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            print(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")
            # Verificar paths sospechosos en entradas de inicio
            for sp in SUSPICIOUS_PATHS:
                if sp in line.lower():
                    alert(f"Entrada de inicio desde path sospechoso: {line}")
                    found_suspicious = True
    except Exception as e:
        warn(f"No se pudo verificar entradas de inicio: {e}")

    # Verificar tareas programadas sospechosas
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.split('\n')
        current_task = ""
        for line in lines:
            if "Nombre de tarea" in line or "Task To Run" in line or "Run As User" in line:
                current_task = line.strip()
            if "AppData\\Local\\Temp" in line or "\\Temp\\" in line:
                alert(f"Tarea programada desde Temp: {current_task}")
                alert(f"  → {line.strip()}")
                found_suspicious = True
    except Exception as e:
        warn(f"No se pudieron verificar tareas programadas: {e}")

    if not found_suspicious:
        ok("No se detectaron entradas de inicio sospechosas")

# ─────────────────────────────────────────────
# MÓDULO 4: SÍNTOMAS GENERALES DE INFECCIÓN
# Detecta: Degradación de rendimiento, auto-ejecución
# ─────────────────────────────────────────────

def check_performance():
    header("MÓDULO 4 — Síntomas de Infección (Rendimiento/Recursos)")

    # CPU
    cpu_percent = psutil.cpu_percent(interval=2)
    if cpu_percent > 80:
        alert(f"CPU al {cpu_percent}% — posible minero de criptomonedas o malware activo")
    elif cpu_percent > 60:
        warn(f"CPU al {cpu_percent}% — uso elevado, monitorear")
    else:
        ok(f"CPU al {cpu_percent}% — normal")

    # RAM
    ram = psutil.virtual_memory()
    if ram.percent > 85:
        alert(f"RAM al {ram.percent}% — posible malware consumiendo memoria")
    elif ram.percent > 70:
        warn(f"RAM al {ram.percent}% — uso elevado")
    else:
        ok(f"RAM al {ram.percent}% — normal")

    # Top 5 procesos por CPU
    info("Top 5 procesos por consumo de CPU:")
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            procs.append(proc.info)
        except:
            continue
    procs.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
    for p in procs[:5]:
        cpu = p.get('cpu_percent', 0) or 0
        color = Fore.RED if cpu > 30 else Fore.YELLOW if cpu > 10 else Fore.WHITE
        print(f"    {color}{p['name']:30} CPU: {cpu:.1f}%{Style.RESET_ALL}")

# ─────────────────────────────────────────────
# MÓDULO 5: REPORTE FINAL
# ─────────────────────────────────────────────

def generate_report():
    header("REPORTE FINAL DE SEGURIDAD")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname  = socket.gethostname()

    print(f"  {Fore.WHITE}Equipo   : {hostname}")
    print(f"  Fecha    : {timestamp}{Style.RESET_ALL}\n")

    alerts   = [f for f in findings if f[0] == "ALERTA"]
    warnings = [f for f in findings if f[0] == "ADVERTENCIA"]

    if not findings:
        print(f"  {Fore.GREEN}{'─'*60}")
        print(f"  ✅  No se detectaron indicadores de compromiso")
        print(f"  {'─'*60}{Style.RESET_ALL}")
    else:
        if alerts:
            print(f"  {Fore.RED}⚠  ALERTAS CRÍTICAS ({len(alerts)}):{Style.RESET_ALL}")
            for _, msg in alerts:
                print(f"    {Fore.RED}→ {msg}{Style.RESET_ALL}")
        if warnings:
            print(f"\n  {Fore.YELLOW}!  ADVERTENCIAS ({len(warnings)}):{Style.RESET_ALL}")
            for _, msg in warnings:
                print(f"    {Fore.YELLOW}→ {msg}{Style.RESET_ALL}")

    # Guardar reporte en JSON
    report = {
        "hostname"  : hostname,
        "timestamp" : timestamp,
        "alerts"    : [m for _, m in alerts],
        "warnings"  : [m for _, m in warnings],
        "summary"   : "LIMPIO" if not findings else "REVISAR"
    }
    report_path = os.path.join(os.path.expanduser("~"), "Desktop", "security_report.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"\n  {Fore.CYAN}📄 Reporte guardado en: {report_path}{Style.RESET_ALL}")
    except Exception:
        pass

    print(f"\n  {Fore.CYAN}{'═'*65}{Style.RESET_ALL}")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print(f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║      🛡️  SECURITY DIAGNOSTIC TOOL — Windows 11                  ║
║         Fortinet NSE1 Threat Landscape Edition                   ║
║         Detecta: Malware · Backdoors · C2 · Spyware · Botnets   ║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

    print(f"  {Fore.YELLOW}[*] Iniciando diagnóstico... esto puede tomar unos segundos{Style.RESET_ALL}")

    check_processes()   # Malware, RATs, Backdoors
    check_network()     # C2, Botnets, Spyware
    check_startup()     # Persistencia, Rootkits
    check_performance() # Síntomas de infección
    generate_report()   # Reporte final

if __name__ == "__main__":
    # Verificar si se ejecuta como administrador
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        print(f"{Fore.YELLOW}[!] Recomendado ejecutar como Administrador para resultados completos")
        print(f"    Click derecho → Ejecutar como administrador{Style.RESET_ALL}\n")

    main()