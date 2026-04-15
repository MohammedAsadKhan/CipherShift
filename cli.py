#!/usr/bin/env python3
"""
cli.py — CipherShift Command Line Interface
Because opening a browser during a CTF costs precious seconds.

Usage:
    python cli.py "CIPHERTEXT"                      # auto-detect & crack
    python cli.py "CIPHERTEXT" -c caesar            # force Caesar
    python cli.py "CIPHERTEXT" -c vigenere          # force Vigenère
    python cli.py "CIPHERTEXT" -c vigenere --lang french
    python cli.py "CIPHERTEXT" -c atbash            # Atbash auto-crack
    python cli.py "CIPHERTEXT" -c railfence         # Rail Fence brute force
    python cli.py "CIPHERTEXT" -c railfence -r 4    # Rail Fence known rails
    python cli.py "CIPHERTEXT" -c playfair -k KEY   # Playfair with known key
    python cli.py "CIPHERTEXT" -c encoding          # Auto-detect encoding
    python cli.py "CIPHERTEXT" -c encoding -e hex   # Force specific encoding
    python cli.py "CIPHERTEXT" -m brute             # brute force all Caesar shifts
    python cli.py "TEXT" -m encrypt -s 13           # ROT13 encrypt
    python cli.py "TEXT" -m decrypt -s 7            # decrypt known shift
    python cli.py "TEXT" -c vigenere -k KEY         # decode Vigenère with known key
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
from classic_ciphers import crack_atbash, crack_rail_fence, crack_playfair, rail_fence_decode, playfair_decode
from cipher_encodings import detect_and_decode, decode_encoding
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

TAGLINE = "Caesar · Vigenère · Atbash · Rail Fence · Playfair · Encodings  |  Built for CTF players"
VERSION = "v1.2.0"


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
            "  [bold cyan]• https://dcode.fr/playfair-cipher[/bold cyan]   ← Playfair without a key\n"
            "  [bold cyan]• https://quipqiup.com[/bold cyan]               ← Substitution ciphers",
            title="[bold]💡 Need More Firepower?[/bold]",
            border_style="yellow",
            padding=(1, 2)
        ))
    else:
        print("\n[TIP] CipherShift works best on easy-medium challenges.")
        print("      Try CyberChef:  https://gchq.github.io/CyberChef")
        print("      Playfair:       https://dcode.fr/playfair-cipher")
        print("      Substitution:   https://quipqiup.com\n")


# ── Caesar Output ─────────────────────────────────────────────────────────────

def print_caesar_result(result: dict, ciphertext: str):
    divider("CAESAR ANALYSIS")

    if RICH:
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Shift:[/bold]       ROT-{result['shift']}\n"
            f"[bold]Confidence:[/bold]  [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(panel_content, title="[bold green]🔓 Best Result[/bold green]", border_style="green"))

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


# ── Atbash Output ─────────────────────────────────────────────────────────────

def print_atbash_result(result: dict):
    divider("ATBASH ANALYSIS")

    if RICH:
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Cipher:[/bold]      Atbash (A↔Z, B↔Y, ...)\n"
            f"[bold]Confidence:[/bold]  [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(
            panel_content,
            title="[bold green]🔓 Atbash Result[/bold green]",
            border_style="green" if result['success'] else "red"
        ))

        if result.get('fallback_message'):
            warn(result['fallback_message'])
            cyberchef_tip()
    else:
        print(f"Cipher:     Atbash")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Decoded:    {result['decoded']}")
        if result.get('fallback_message'):
            print(f"\n[WARN] {result['fallback_message']}")


# ── Rail Fence Output ─────────────────────────────────────────────────────────

def print_rail_fence_result(result: dict):
    divider("RAIL FENCE ANALYSIS")

    if RICH:
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Best Rail Count:[/bold]  {result['rails']} rails\n"
            f"[bold]Confidence:[/bold]       [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(
            panel_content,
            title="[bold green]🔓 Rail Fence Result[/bold green]",
            border_style="green" if result['success'] else "red"
        ))

        # Show all brute force results in a table
        if result.get('all_results'):
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", border_style="dim")
            table.add_column("Rails", width=8)
            table.add_column("Conf", width=8)
            table.add_column("Bar", width=22)
            table.add_column("Decoded Preview")

            for r in result['all_results']:
                c = r['confidence']
                color = "green" if c >= 70 else "yellow" if c >= 40 else "red"
                bar = "█" * int(c / 5) + "░" * (20 - int(c / 5))
                table.add_row(
                    f"{r['rails']}",
                    f"[{color}]{c:.1f}%[/{color}]",
                    f"[{color}]{bar}[/{color}]",
                    r['text'][:55]
                )
            console.print(Panel(table, title="[bold]All Rail Counts Ranked[/bold]", border_style="dim"))

        if result.get('fallback_message'):
            warn(result['fallback_message'])
            cyberchef_tip()
    else:
        print(f"Best Rails: {result['rails']}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Decoded:    {result['decoded']}")
        print("\nAll results:")
        for r in result.get('all_results', []):
            print(f"  Rails {r['rails']:2d} ({r['confidence']:5.1f}%): {r['text'][:55]}")
        if result.get('fallback_message'):
            print(f"\n[WARN] {result['fallback_message']}")


# ── Playfair Output ───────────────────────────────────────────────────────────

def print_playfair_result(result: dict):
    divider("PLAYFAIR ANALYSIS")

    if not result['success'] and not result.get('decoded'):
        # No key provided — honest redirect
        if RICH:
            console.print(Panel(
                "[yellow]Playfair auto-crack is not supported — it's computationally hard "
                "without a key.\n\n"
                "If you have the key, re-run with [bold cyan]-k YOURKEY[/bold cyan]\n\n"
                "Otherwise try:\n"
                "  [bold cyan]• https://www.dcode.fr/playfair-cipher[/bold cyan]\n"
                "  [bold cyan]• https://gchq.github.io/CyberChef[/bold cyan]",
                title="[bold red]🔒 Playfair — Key Required[/bold red]",
                border_style="red"
            ))
        else:
            print("[PLAYFAIR] Auto-crack not supported. Provide a key with -k.")
            print("  Try: https://www.dcode.fr/playfair-cipher")
        return

    if RICH:
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Key:[/bold]         [bold magenta]{result['key']}[/bold magenta]\n"
            f"[bold]Confidence:[/bold]  [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(
            panel_content,
            title="[bold green]🔓 Playfair Result[/bold green]",
            border_style="magenta"
        ))

        if result.get('fallback_message'):
            warn(result['fallback_message'])
            cyberchef_tip()
    else:
        print(f"Key:        {result['key']}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Decoded:    {result['decoded']}")
        if result.get('fallback_message'):
            print(f"\n[WARN] {result['fallback_message']}")


# ── Encoding Output ───────────────────────────────────────────────────────────

def print_encoding_result(result: dict):
    divider("ENCODING ANALYSIS")

    if not result['detected']:
        if RICH:
            console.print(Panel(
                "[yellow]No supported encoding detected.\n\n"
                "Tried: Binary → Hex → Base32 → Base64 → ROT47\n\n"
                "For unknown encodings, try CyberChef's [bold cyan]'Magic'[/bold cyan] operation:\n"
                "  [bold cyan]https://gchq.github.io/CyberChef[/bold cyan]",
                title="[bold red]🔍 No Encoding Detected[/bold red]",
                border_style="red"
            ))
        else:
            print("[ENCODING] No encoding detected.")
            print("  Try CyberChef Magic: https://gchq.github.io/CyberChef")
        return

    if RICH:
        chain = " → ".join(result['encoding_chain'])
        conf = result['confidence']
        conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
        conf_bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))

        panel_content = (
            f"[bold]Encoding Chain:[/bold]  [bold magenta]{chain}[/bold magenta]\n"
            f"[bold]Layers:[/bold]          {result['layers']}\n"
            f"[bold]Confidence:[/bold]      [{conf_color}]{conf:.1f}%  {conf_bar}[/{conf_color}]\n\n"
            f"[bold]Decoded:[/bold]\n[bold cyan]{result['decoded']}[/bold cyan]"
        )
        console.print(Panel(
            panel_content,
            title="[bold green]🔓 Encoding Detected & Decoded[/bold green]",
            border_style="green"
        ))

        if result.get('fallback_message'):
            warn(result['fallback_message'])
    else:
        chain = " -> ".join(result['encoding_chain'])
        print(f"Encoding:   {chain}")
        print(f"Layers:     {result['layers']}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Decoded:    {result['decoded']}")
        if result.get('fallback_message'):
            print(f"\n[WARN] {result['fallback_message']}")


# ── Auto-Detect ───────────────────────────────────────────────────────────────

def auto_detect_cipher(ciphertext: str) -> str:
    """
    Heuristic: determine most likely cipher/encoding type.

    Order of checks:
    1. Looks like an encoding (binary/hex/base64)? → encoding
    2. IoC too low for Caesar? → vigenere
    3. Default → caesar
    """
    import re

    text_clean = ciphertext.strip().replace(' ', '').replace('\n', '')

    # Check for obvious encodings first
    if re.match(r'^[01]+$', text_clean) and len(text_clean) % 8 == 0:
        return 'encoding'
    if re.match(r'^[0-9a-fA-F]+$', text_clean) and len(text_clean) % 2 == 0 and len(text_clean) >= 8:
        return 'encoding'
    if re.match(r'^[A-Za-z0-9+/=]+$', text_clean) and len(text_clean) % 4 == 0 and len(text_clean) >= 8:
        return 'encoding'

    # IoC-based cipher detection
    ioc = index_of_coincidence(ciphertext)
    if ioc < 0.050 and len([c for c in ciphertext if c.isalpha()]) >= 40:
        return 'vigenere'

    return 'caesar'


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='ciphershift',
        description='CipherShift — Multi-Cipher Toolkit for CTF Players',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
cipher types (-c):
  auto        Auto-detect cipher type (default)
  caesar      Caesar / ROT-N cipher
  vigenere    Vigenère polyalphabetic cipher
  atbash      Atbash cipher (A↔Z, B↔Y, ...)
  railfence   Rail Fence transposition cipher
  playfair    Playfair digraph cipher (requires -k for decode)
  encoding    Encoding detection (Base64, Hex, Binary, ROT47, Base32)

examples:
  python cli.py "KHOOR ZRUOG"
  python cli.py "KHOOR ZRUOG" -m brute
  python cli.py "NWPCL BDDLZ" -c atbash
  python cli.py "WKHHQMBLVQB" -c railfence
  python cli.py "CIPHERTEXT" -c railfence -r 3
  python cli.py "CIPHERTEXT" -c playfair -k SECRETKEY
  python cli.py "SGVsbG8gV29ybGQ=" -c encoding
  python cli.py "CIPHERTEXT" -c encoding -e base64
  python cli.py "encryptedtext" -c vigenere --lang french
  python cli.py "Hello World" -m encrypt -s 13
  python cli.py "Uryyb Jbeyq" -m decrypt -s 13

works best on:  easy-medium CTF challenges, 30+ character ciphertext
if it fails:    try dcode.fr or CyberChef (no shame, we'll tell you)
        """
    )

    parser.add_argument('text', help='Ciphertext (or plaintext for encrypt mode)')
    parser.add_argument('-c', '--cipher',
                        choices=['auto', 'caesar', 'vigenere', 'atbash', 'railfence', 'playfair', 'encoding'],
                        default='auto',
                        help='Cipher/encoding type (default: auto-detect)')
    parser.add_argument('-m', '--mode', choices=['crack', 'brute', 'encrypt', 'decrypt'], default='crack',
                        help='Operation mode (default: crack)')
    parser.add_argument('-s', '--shift', type=int, default=13,
                        help='Shift value for Caesar encrypt/decrypt (default: 13)')
    parser.add_argument('-k', '--key', type=str, default=None,
                        help='Known key for Vigenère or Playfair decode')
    parser.add_argument('-r', '--rails', type=int, default=None,
                        help='Known rail count for Rail Fence decode (omit to brute force)')
    parser.add_argument('-e', '--encoding', type=str, default=None,
                        help='Force specific encoding: base64, hex, binary, rot47, base32')
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

    # ── Encrypt / Decrypt (Caesar only) ──────────────────────────────────────
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

    # ── Brute Force (Caesar) ──────────────────────────────────────────────────
    if args.mode == 'brute':
        results = brute_force(ciphertext)
        print_brute_force(results, top_n=args.top)
        return

    # ── Crack Mode ────────────────────────────────────────────────────────────
    cipher_type = args.cipher
    if cipher_type == 'auto':
        cipher_type = auto_detect_cipher(ciphertext)
        if RICH:
            console.print(f"[dim]Auto-detected:[/dim] [bold]{cipher_type.capitalize()}[/bold]")
        else:
            print(f"Auto-detected: {cipher_type}")

    # ── Caesar ────────────────────────────────────────────────────────────────
    if cipher_type == 'caesar':
        result = auto_crack(ciphertext)
        print_caesar_result(result, ciphertext)
        if result.get('vigenere_flag'):
            if RICH:
                console.print("\n[yellow]Tip:[/yellow] Re-run with [bold cyan]-c vigenere[/bold cyan] to try polyalphabetic cracking.")
            if result['confidence'] < 35:
                cyberchef_tip()

    # ── Vigenère ──────────────────────────────────────────────────────────────
    elif cipher_type == 'vigenere':
        if args.key:
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
            result = crack_vigenere(ciphertext, language=args.lang)
            print_vigenere_result(result)

    # ── Atbash ────────────────────────────────────────────────────────────────
    elif cipher_type == 'atbash':
        result = crack_atbash(ciphertext)
        print_atbash_result(result)

    # ── Rail Fence ────────────────────────────────────────────────────────────
    elif cipher_type == 'railfence':
        if args.rails:
            # Known rails — just decode
            from classic_ciphers import rail_fence_decode
            decoded = rail_fence_decode(ciphertext, args.rails)
            from frequency import compute_confidence
            confidence = compute_confidence(decoded)
            result = {
                'success': confidence >= 40,
                'rails': args.rails,
                'decoded': decoded,
                'confidence': confidence,
                'all_results': [{'rails': args.rails, 'text': decoded, 'confidence': confidence}],
                'fallback_message': None if confidence >= 40 else (
                    f"Low confidence ({confidence:.1f}%). Rail count may be wrong. "
                    "Try CyberChef: https://gchq.github.io/CyberChef"
                )
            }
        else:
            result = crack_rail_fence(ciphertext)
        print_rail_fence_result(result)

    # ── Playfair ──────────────────────────────────────────────────────────────
    elif cipher_type == 'playfair':
        result = crack_playfair(ciphertext, key=args.key)
        print_playfair_result(result)

    # ── Encoding ──────────────────────────────────────────────────────────────
    elif cipher_type == 'encoding':
        if args.encoding:
            result = decode_encoding(ciphertext, args.encoding)
            # Normalize to same shape as detect_and_decode for printer
            normalized = {
                'detected': result['success'],
                'encoding_chain': [result['encoding']] if result['success'] else [],
                'decoded': result.get('decoded') or ciphertext,
                'layers': 1 if result['success'] else 0,
                'confidence': result['confidence'],
                'fallback_message': result.get('fallback_message')
            }
        else:
            normalized = detect_and_decode(ciphertext)
        print_encoding_result(normalized)

    divider()
    if RICH:
        console.print(f"[dim]CipherShift {VERSION} | github.com/yourusername/caesar-cipher-analyzer[/dim]\n")
    else:
        print(f"CipherShift {VERSION}\n")


if __name__ == '__main__':
    main()
