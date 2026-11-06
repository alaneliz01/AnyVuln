import os
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
import tkinter as tk
from tkinter import filedialog

console = Console()

def limpiar_pantalla():
    os.system('cls' if os.name == 'nt' else 'clear')

#extraccion de archivo
def seleccionar_archivo():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    ruta = filedialog.askopenfilename(
        title="Selecciona el CSV o Excel",
        filetypes=[("Archivos de datos", "*.csv *.xlsx *.xls")]
    )
    root.destroy()
    return ruta

def analizar_remediacion():
    limpiar_pantalla()
    console.print(Panel("[bold cyan]Analizador de Remediaciones - Workstations[/bold cyan]", expand=False))

    #vulns totales
    total_input = Prompt.ask(
        "[bold yellow]Ingresa el total global de vulnerabilidades[/bold yellow]",
        default="227,473"
    )
    total_global_vulns = int(total_input.replace(",", "").replace(".", "").strip())

    kb_nombre = Prompt.ask(
        "[bold yellow]Ingresa el código del KB[/bold yellow]",
        default="KB5127648"
    )

    #extraccion de archivo
    ruta_archivo = seleccionar_archivo()
    if not ruta_archivo:
        console.print("[bold red]No se seleccionó ningún archivo.[/bold red]")
        return

    if ruta_archivo.endswith('.csv'):
        df = pd.read_csv(ruta_archivo, low_memory=False)
    else:
        df = pd.read_excel(ruta_archivo)

    #Analisis
    vulns_fixed = len(df)
    porcentaje_global = (vulns_fixed / total_global_vulns) * 100 if total_global_vulns > 0 else 0

    series_exprt = df['ExPRT rating'].astype(str).str.strip().str.capitalize()
    conteo_exprt = series_exprt.value_counts()
    critical_count = int(conteo_exprt.get('Critical', 0))
    high_count = int(conteo_exprt.get('High', 0))

    crit_pct = (critical_count / vulns_fixed) * 100 if vulns_fixed > 0 else 0
    high_pct = (high_count / vulns_fixed) * 100 if vulns_fixed > 0 else 0

    assets_afectados = df['Hostname'].nunique()
    productos = ", ".join(df['Vulnerable product versions'].dropna().unique()[:3])

    tabla = Table(
        title=f"Install {kb_nombre} (Total Global: {total_global_vulns:,})",
        show_header=True,
        header_style="bold white on green",
        show_lines=True
    )
    tabla.add_column("Apartado en Slide", style="bold cyan", width=32)
    tabla.add_column("Valor Exacto", style="yellow", width=30)
    tabla.add_column("Texto para PPT", style="bold green", width=42)

    tabla.add_row("Círculo Superior (XX%)", f"{porcentaje_global:.2f}%", f"{round(porcentaje_global)}%")
    tabla.add_row("Título", kb_nombre, f"Install {kb_nombre}")
    tabla.add_row("C / H (%)", f"C: {crit_pct:.2f}% | H: {high_pct:.2f}%", f"C: {round(crit_pct)}% | H: {round(high_pct)}%")
    tabla.add_row("Bullet 1", f"{vulns_fixed:,} ({porcentaje_global:.2f}%)", f"{vulns_fixed:,} vulnerabilities will be fixed ({round(porcentaje_global)}%)")
    tabla.add_row("Bullet 2", f"C: {critical_count:,} | H: {high_count:,}", f"{critical_count:,} critical and {high_count:,} high")
    tabla.add_row("Bullet 4 (Affected assets)", productos, f"Affected assets: {productos}")
    tabla.add_row("Recuadro Inferior (Assets)", f"{assets_afectados} Hostnames únicos", f"{assets_afectados} Assets")

    console.print(tabla)

if __name__ == "__main__":
    analizar_remediacion()