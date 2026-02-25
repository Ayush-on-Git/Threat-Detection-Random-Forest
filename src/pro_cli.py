from threat_engine import analyze_url
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.text import Text

console = Console()


def threat_bar(score):
    blocks = int(score / 5)
    bar = "█" * blocks + "-" * (20 - blocks)

    if score < 30:
        color = "green"
    elif score < 60:
        color = "yellow"
    else:
        color = "red"

    return f"[{color}]{bar}[/] {score}/100"


def display_result(result):
    console.rule("[bold cyan]URL Threat Intelligence Report[/bold cyan]")

    prediction_color = "green" if result["prediction"] == 0 else "red"
    prediction_text = "SAFE" if result["prediction"] == 0 else "MALICIOUS"

    table = Table(show_header=False)
    table.add_row("Domain", result["domain"])
    table.add_row("Probability", f"{result['probability'] * 100:.2f}%")
    table.add_row("Prediction", f"[{prediction_color}]{prediction_text}[/]")
    table.add_row("Threat Score", threat_bar(result["threat_score"]))
    table.add_row("Risk Level", f"[bold]{result['risk_level']}[/]")

    console.print(table)

    console.print("\n[bold]Risk Factors:[/bold]")
    for reason in result["reasons"]:
        console.print(f" • {reason}")

    console.rule()


def main():
    console.print("[bold magenta]🚀 Advanced URL Threat Analyzer[/bold magenta]\n")

    while True:
        url = console.input("[bold yellow]Enter URL (type 'exit' to quit): [/bold yellow]")

        if url.lower() == "exit":
            console.print("\n[bold cyan]Goodbye! Stay Safe Online 🛡️[/bold cyan]")
            break

        try:
            result = analyze_url(url)
            display_result(result)
        except Exception as e:
            console.print(f"[red]Error analyzing URL:[/] {e}")


if __name__ == "__main__":
    main()