#!/usr/bin/env python3
"""
cli.py — CipherShift Command Line Interface
Because opening a browser during a CTF costs precious seconds.

Usage:
    python cli.py "CIPHERTEXT"               # auto-detect & crack
    python cli.py "CIPHERTEXT" -c caesar     # force Caesar
    python cli.py "CIPHERTEXT" -c vigenere   # force Vigenère
    python cli.py "CIPHERTEXT" -c vigenere --lang french
    python cli.py "CIPHERTEXT" -m brute      # brute force all shifts
    python cli.py "TEXT" -m encrypt -s 13    # ROT13 encrypt
    python cli.py "TEXT" -m decrypt -s 7     # decrypt known shift
    python cli.py "TEXT" -c vigenere -k KEY  # decode with known key
"""

import argparse
import sys
import os
import time

# ── Try to import rich, fall back to plain if not installed ──────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH = True
except ImportError:
    RICH = False

from analyzer import auto_crack, encrypt, decrypt, brute_force
from vigenere import crack_vigenere, vigenere_decode, vigenere_encode
from frequency import index_of_coincidence

console = Console() if RICH else None

# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = r"""
   ___  _      _               ___ _    _  __ _
  / __\(_)_ __| |__   ___ _ __/ __| |_ (_)/ _| |_
 / /   | | '_ \ '_ \ / _ \ '__\__ \ ' \| |  _| __|
/ /___ | | |_) | | | |  __/ |  ___/ | | | | | | |_
\____/ |_| .__/|_| |_|\___|_| |____/_| |_|_|_|  \__|
          |_|
"""

TAGLINE = "Caesar & Vigenère Cipher Toolkit  |  Built for CTF players, by a CTF player"
VERSION = "v1.1.0"


def print_banner():
    if RICH:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        console.print(f"  [dim]{TAGLINE}[/dim]  [bold yellow]{VERSION}[/bold yellow]\n")
    else:
        print(BANNER)
        print(f"  {TAGLINE}  {VERSION}\n")


def divider(title: str = ""):
    if RICH:
        console.print(Rule(f"[bold dim]{title}[/bold dim]", style="dim cyan"))
    else:
        print(f"\n{'─' * 60}  {title}\n")


def success(msg: str):
    if RICH:
        console.print(f"[bold green]✔[/bold green]  {msg}")
    else:
        print(f"[OK] {msg}")


def warn(msg: str):
    if RICH:
        console.print(f"[bold yellow]⚠[/bold yellow]  {msg}")
    else:
        print(f"[WARN] {msg}")


def error(msg: str):
    if RICH:
        console.print(f"[bold red]✘[/bold red]  {msg}")
    else:
        print(f"[ERR] {msg}")


def cyberchef_tip():
    """Print the 'try CyberChef' tip — no shame, just pragmatism."""
    if RICH:
        console.print(Panel(
            "[yellow]CipherShift works best on easy-medium CTF challenges.\n"
            "For harder ciphers, short texts, or unknown cipher types, try:\n\n"
            "  [bold cyan]• https://gchq.github.io/CyberChef[/bold cyan]   ← Swiss Army knife\n"
            "  [bold cyan]• https://dcode.fr/vigenere-cipher[/bold cyan]   ← Best for French Vigenère\n"
            "  [bold cyan]• https://quipqiup.com[/bold cyan]               ← Substitution ciphers",
            title="[bold]💡 Need More Firepower?[/bold]",
            border_style="yellow",
            padding=(1, 2)
        ))
    else:
        print("\n[TIP] CipherShift works best on easy-medium challenges.")
        print("      Try CyberChef: https://gchq.github.io/CyberChef")
        print("      Or dcode.fr for French Vigenere: https://dcode.fr/vigenere-cipher\n")


# ── Caesar Output ─────────────────────────────────────────────────────────────

def print_caesar_result(result: dict, ciphertext: str):
    divider("CAESAR ANALYSIS")

    if RICH:
        # Main result panel
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Shift:[/bold]       ROT-{result['shift']}\n"
            f"[bold]Confidence:[/bold]  [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(panel_content, title="[bold green]🔓 Best Result[/bold green]", border_style="green"))

        # Flags
        flags = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        flags.add_column(style="dim")
        flags.add_column()

        rot13_val = "[bold yellow]YES — Classic ROT13[/bold yellow]" if result.get('is_rot13') else "[green]No[/green]"
        vig_val = "[bold red]⚠ POSSIBLE — IoC too low for Caesar[/bold red]" if result.get('vigenere_flag') else "[green]No[/green]"

        de = result.get('double_encode')
        if de and de.get('detected'):
            de_val = f"[bold red]YES — Shift {de['first_shift']} then Shift {de['second_shift']}[/bold red]"
        else:
            de_val = "[green]No[/green]"

        flags.add_row("ROT13 Detected:", rot13_val)
        flags.add_row("Vigenère Suspected:", vig_val)
        flags.add_row("Double Encoding:", de_val)

        console.print(Panel(flags, title="[bold]🚩 Detection Flags[/bold]", border_style="dim"))

        if result.get('vigenere_flag'):
            warn("Vigenère flag triggered! Re-run with [bold]-c vigenere[/bold] or try dcode.fr")

    else:
        print(f"Shift:      ROT-{result['shift']}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Decoded:    {result['decoded']}")
        print(f"ROT13:      {'YES' if result.get('is_rot13') else 'No'}")
        print(f"Vigenere?:  {'POSSIBLE' if result.get('vigenere_flag') else 'No'}")


def print_brute_force(results: list, top_n: int = 10):
    divider(f"BRUTE FORCE — TOP {top_n}")
    if RICH:
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Rank", style="dim", width=6)
        table.add_column("Shift", width=8)
        table.add_column("Conf", width=8)
        table.add_column("Bar", width=22)
        table.add_column("Decoded Preview")

        for i, r in enumerate(results[:top_n], 1):
            conf = r['confidence']
            color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
            bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))
            rank_icon = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"  {i}"
            table.add_row(
                rank_icon,
                f"ROT-{r['shift']}",
                f"[{color}]{conf:.1f}%[/{color}]",
                f"[{color}]{bar}[/{color}]",
                r['text'][:55]
            )
        console.print(table)
    else:
        for i, r in enumerate(results[:top_n], 1):
            print(f"#{i:2d} ROT{r['shift']:2d} ({r['confidence']:5.1f}%): {r['text'][:55]}")


# ── Vigenère Output ───────────────────────────────────────────────────────────

def print_vigenere_result(result: dict):
    divider("VIGENÈRE ANALYSIS")

    if not result['success']:
        error("Vigenère crack failed or confidence too low.")
        if result.get('fallback_message'):
            warn(result['fallback_message'])
        cyberchef_tip()
        return

    if RICH:
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Key:[/bold]         [bold magenta]{result['key']}[/bold magenta]\n"
            f"[bold]Key Length:[/bold]  {result['key_length']}\n"
            f"[bold]Language:[/bold]    {result['language'].capitalize()}\n"
            f"[bold]Confidence:[/bold]  [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(panel_content, title="[bold green]🔓 Vigenère Result[/bold green]", border_style="magenta"))

        if result.get('fallback_message'):
            warn(result['fallback_message'])
            cyberchef_tip()
    else:
        print(f"Key:        {result['key']}")
        print(f"Key Length: {result['key_length']}")
        print(f"Language:   {result['language']}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Decoded:    {result['decoded']}")
        if result.get('fallback_message'):
            print(f"\n[WARN] {result['fallback_message']}")


# ── Auto-Detect ───────────────────────────────────────────────────────────────

def auto_detect_cipher(ciphertext: str) -> str:
    """
    Heuristic: use IoC to guess whether this is Caesar or Vigenère.
    Returns 'caesar' or 'vigenere'.
    """
    ioc = index_of_coincidence(ciphertext)
    # IoC near 0.065 → likely Caesar (mono-alphabetic)
    # IoC significantly lower → polyalphabetic (Vigenère)
    if ioc < 0.050 and len([c for c in ciphertext if c.isalpha()]) >= 40:
        return 'vigenere'
    return 'caesar'


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='ciphershift',
        description='CipherShift — Caesar & Vigenère Cipher Toolkit for CTF Players',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python cli.py "KHOOR ZRUOG"
  python cli.py "KHOOR ZRUOG" -m brute
  python cli.py "encryptedtext" -c vigenere --lang french
  python cli.py "encryptedtext" -c vigenere -k SECRETKEY
  python cli.py "Hello World" -m encrypt -s 13
  python cli.py "Uryyb Jbeyq" -m decrypt -s 13

works best on:  easy-medium CTF challenges, 30+ character ciphertext
if it fails:    try dcode.fr or CyberChef (no shame, we'll tell you)
        """
    )

    parser.add_argument('text', help='Ciphertext (or plaintext for encrypt mode)')
    parser.add_argument('-c', '--cipher', choices=['auto', 'caesar', 'vigenere'], default='auto',
                        help='Cipher type (default: auto-detect)')
    parser.add_argument('-m', '--mode', choices=['crack', 'brute', 'encrypt', 'decrypt'], default='crack',
                        help='Operation mode (default: crack)')
    parser.add_argument('-s', '--shift', type=int, default=13,
                        help='Shift value for Caesar encrypt/decrypt (default: 13)')
    parser.add_argument('-k', '--key', type=str, default=None,
                        help='Known key for Vigenère decode')
    parser.add_argument('--lang', choices=['auto', 'english', 'french'], default='auto',
                        help='Language for Vigenère frequency analysis (default: auto)')
    parser.add_argument('--top', type=int, default=10,
                        help='Number of results to show in brute force mode (default: 10)')
    parser.add_argument('--no-banner', action='store_true',
                        help='Skip the banner (for piping output)')

    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    ciphertext = args.text

    # ── Encrypt / Decrypt (Caesar only for now) ───────────────────────────────
    if args.mode == 'encrypt':
        result = encrypt(ciphertext, args.shift)
        divider(f"ENCRYPTED  ROT-{args.shift}")
        if RICH:
            console.print(Panel(f"[bold cyan]{result}[/bold cyan]", border_style="cyan"))
        else:
            print(result)
        return

    if args.mode == 'decrypt':
        result = decrypt(ciphertext, args.shift)
        divider(f"DECRYPTED  ROT-{args.shift}")
        if RICH:
            console.print(Panel(f"[bold cyan]{result}[/bold cyan]", border_style="cyan"))
        else:
            print(result)
        return

    # ── Brute Force ───────────────────────────────────────────────────────────
    if args.mode == 'brute':
        results = brute_force(ciphertext)
        print_brute_force(results, top_n=args.top)
        return

    # ── Crack Mode ────────────────────────────────────────────────────────────
    cipher_type = args.cipher
    if cipher_type == 'auto':
        cipher_type = auto_detect_cipher(ciphertext)
        if RICH:
            console.print(f"[dim]Auto-detected cipher type:[/dim] [bold]{cipher_type.capitalize()}[/bold]")
        else:
            print(f"Auto-detected: {cipher_type}")

    if cipher_type == 'caesar':
        result = auto_crack(ciphertext)
        print_caesar_result(result, ciphertext)

        # If Vigenère flag triggered, suggest re-running
        if result.get('vigenere_flag'):
            if RICH:
                console.print("\n[yellow]Tip:[/yellow] Re-run with [bold cyan]-c vigenere[/bold cyan] to try polyalphabetic cracking.")
            if result['confidence'] < 35:
                cyberchef_tip()

    elif cipher_type == 'vigenere':
        if args.key:
            # Known key — just decode
            decoded = vigenere_decode(ciphertext, args.key)
            divider(f"VIGENÈRE DECODE  key={args.key.upper()}")
            if RICH:
                console.print(Panel(
                    f"[bold]Key:[/bold] [magenta]{args.key.upper()}[/magenta]\n\n"
                    f"[bold]Decoded:[/bold]\n[bold cyan]{decoded}[/bold cyan]",
                    title="[bold green]🔓 Vigenère Decoded[/bold green]",
                    border_style="magenta"
                ))
            else:
                print(f"Key:     {args.key.upper()}")
                print(f"Decoded: {decoded}")
        else:
            # Auto-crack
            result = crack_vigenere(ciphertext, language=args.lang)
            print_vigenere_result(result)

    divider()
    if RICH:
        console.print(f"[dim]CipherShift {VERSION} | github.com/yourusername/caesar-cipher-analyzer[/dim]\n")
    else:
        print(f"CipherShift {VERSION}\n")


if __name__ == '__main__':
    main()
