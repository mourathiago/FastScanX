import argparse
import socket
import json
import csv
import datetime
import shodan
import os
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

# Banner ASCII em verde
BANNER = """[green]
███████╗ █████╗ ███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
█████╗  ███████║███████╗   ██║   ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
██╔══╝  ██╔══██║╚════██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
██║     ██║  ██║███████║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                          FastScanX v1.4.4 by Thiago Moura
[/green]"""

# Configuração Shodan
def carregar_config():
    if os.path.exists("config.json"):
        with open("config.json") as f:
            return json.load(f)
    return {}

def consultar_shodan(api_key, ip):
    try:
        api = shodan.Shodan(api_key)
        return api.host(ip)
    except Exception as e:
        return {"error": str(e)}

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        banner = ""
        if result == 0:
            try:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                pass
            return {"ip": ip, "port": port, "status": "open", "banner": banner}
    except:
        pass
    finally:
        sock.close()
    return None

def exportar_resultados(resultados, formato):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"fastscanx_{timestamp}.{formato}"
    if formato == "json":
        with open(filename, "w") as f:
            json.dump([r for r in resultados if r], f, indent=2)
    elif formato == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=resultados[0].keys())
            writer.writeheader()
            for r in resultados:
                if r:
                    writer.writerow(r)
    console.print(f"[green]Exportado para {filename}[/green]")

# Argumentos
parser = argparse.ArgumentParser()
parser.add_argument("ip", help="Endereço IP para escanear")
parser.add_argument("-p", "--ports", help="Intervalo de portas, ex: 20-80", default="20-1024")
parser.add_argument("--export", choices=["json", "csv"], help="Exportar resultados")
parser.add_argument("--verbose", action="store_true", help="Mostrar resultados detalhados")
parser.add_argument("--shodan", action="store_true", help="Consultar dados adicionais com Shodan")
parser.add_argument("--ui", action="store_true", help="Interface interativa com textual")
args = parser.parse_args()

console.print(BANNER)
console.print(f"[cyan]Iniciando varredura em {args.ip} às {datetime.datetime.now()}[/cyan]")

porta_inicio, porta_fim = map(int, args.ports.split("-"))
resultados = []

for port in track(range(porta_inicio, porta_fim + 1), description="Escaneando..."):
    resultado = scan_port(args.ip, port)
    if resultado:
        resultados.append(resultado)

if args.shodan:
    config = carregar_config()
    shodan_data = consultar_shodan(config.get("shodan_api_key", ""), args.ip)
    for r in resultados:
        if r:
            r.update({
                "org": shodan_data.get("org"),
                "os": shodan_data.get("os"),
                "hostnames": ", ".join(shodan_data.get("hostnames", [])),
                "city": shodan_data.get("city"),
                "region": shodan_data.get("region_code"),
                "country": shodan_data.get("country_name"),
                "latitude": shodan_data.get("latitude"),
                "longitude": shodan_data.get("longitude"),
                "tags": ", ".join(shodan_data.get("tags", [])),
                "asn": shodan_data.get("asn"),
                "isp": shodan_data.get("isp"),
                "domain": ", ".join(shodan_data.get("domains", [])),
                "vulns": ", ".join(shodan_data.get("vulns", [])) if shodan_data.get("vulns") else ""
            })

if args.export and resultados:
    exportar_resultados(resultados, args.export)

# Importa Textual apenas se a UI for solicitada
if args.ui:
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Header, Footer, DataTable

        class ScanApp(App):
            def __init__(self, dados, **kwargs):
                super().__init__(**kwargs)
                self.dados = dados

            def compose(self) -> ComposeResult:
                yield Header()
                table = DataTable()
                table.add_columns("IP", "Porta", "Status", "Banner")
                for r in self.dados:
                    if r:
                        table.add_row(str(r["ip"]), str(r["port"]), r["status"], r["banner"])
                yield table
                yield Footer()

        app = ScanApp(resultados)
        app.run()

    except ModuleNotFoundError:
        console.print("[red]Erro: módulo 'textual' não encontrado.[/red]")
        console.print("Instale com: [yellow]pip install textual[/yellow]")
        exit(1)

console.print(f"[cyan]Finalizado em {datetime.datetime.now()}[/cyan]")
