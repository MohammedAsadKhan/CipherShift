"""
report.py — PDF Analysis Report Generator
CipherShift: For when you need to document your CTF solve
or just want to flex on your team with a professional-looking PDF.

"A well-formatted PDF report makes even ROT13 look like real work." — Sun Tzu (probably)
"""

from fpdf import FPDF
from datetime import datetime
from frequency import get_letter_frequencies, ENGLISH_FREQ


class CipherReport(FPDF):
    """
    Custom FPDF subclass with CipherShift branding.
    Because plain PDFs are for people who don't care.
    """

    def header(self):
        self.set_font('Helvetica', 'B', 14)
        self.set_fill_color(30, 30, 50)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, '  CipherShift — Analysis Report', fill=True, new_x='LMARGIN', new_y='NEXT')
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'CipherShift | Page {self.page_no()} | Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}', align='C')

    def section_title(self, title: str):
        self.set_font('Helvetica', 'B', 11)
        self.set_fill_color(240, 240, 250)
        self.set_text_color(20, 20, 80)
        self.cell(0, 8, f'  {title}', fill=True, new_x='LMARGIN', new_y='NEXT')
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def key_value_row(self, key: str, value: str, highlight: bool = False):
        self.set_font('Helvetica', 'B', 10)
        self.set_fill_color(248, 248, 255) if highlight else self.set_fill_color(255, 255, 255)
        self.cell(55, 7, f'  {key}:', fill=highlight, border=0)
        self.set_font('Helvetica', '', 10)
        self.cell(0, 7, f'  {value}', fill=highlight, border=0, new_x='LMARGIN', new_y='NEXT')


def generate_report(
    ciphertext: str,
    result: dict,
    mode: str = "Auto-Crack"
) -> bytes:
    """
    Generate a full PDF analysis report for a cipher analysis session.

    Args:
        ciphertext: The original input ciphertext
        result: The analysis result dict from auto_crack() or manual decode
        mode: 'Auto-Crack', 'Manual Decrypt', or 'Brute Force'

    Returns:
        PDF as bytes — ready to be downloaded directly from Streamlit.
    """
    pdf = CipherReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_margins(15, 15, 15)

    # ── Timestamp & Mode ──────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, f'Generated: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}  |  Mode: {mode}', new_x='LMARGIN', new_y='NEXT')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # ── Input Ciphertext ──────────────────────────────────────────────────────
    pdf.section_title('Input Ciphertext')
    pdf.set_font('Courier', '', 10)
    pdf.set_fill_color(245, 245, 245)
    # Truncate for display if very long
    display_cipher = ciphertext[:500] + ('...' if len(ciphertext) > 500 else '')
    pdf.multi_cell(0, 6, f'  {display_cipher}', fill=True)
    pdf.ln(4)

    # ── Analysis Results ──────────────────────────────────────────────────────
    pdf.section_title('Analysis Results')

    shift = result.get('shift', 'N/A')
    decoded = result.get('decoded', result.get('text', 'N/A'))
    confidence = result.get('confidence', 0.0)

    pdf.key_value_row('Best Shift', str(shift), highlight=True)
    pdf.key_value_row('Confidence Score', f'{confidence:.1f}%', highlight=True)

    # Confidence interpretation
    if confidence >= 80:
        interp = 'Very High — Almost certainly correct'
    elif confidence >= 50:
        interp = 'Medium — Likely correct, verify manually'
    elif confidence >= 25:
        interp = 'Low — Possible but uncertain'
    else:
        interp = 'Very Low — May not be English or Caesar'
    pdf.key_value_row('Confidence Level', interp)
    pdf.ln(2)

    pdf.section_title('Decoded Text')
    pdf.set_font('Courier', '', 10)
    pdf.set_fill_color(240, 255, 240)
    display_decoded = decoded[:500] + ('...' if len(str(decoded)) > 500 else '')
    pdf.multi_cell(0, 6, f'  {display_decoded}', fill=True)
    pdf.ln(4)

    # ── Detection Flags ───────────────────────────────────────────────────────
    pdf.section_title('Detection Flags')
    is_rot13 = result.get('is_rot13', False)
    double_encode = result.get('double_encode')
    vigenere_flag = result.get('vigenere_flag', False)

    pdf.key_value_row('ROT13 Detected', 'YES — Shift is 13, classic obfuscation move.' if is_rot13 else 'No')
    pdf.key_value_row('Vigenère Suspected', 'YES — IoC too low for Caesar. Try a polyalphabetic tool.' if vigenere_flag else 'No')

    if double_encode and double_encode.get('detected'):
        pdf.key_value_row('Double Encoding', f"YES — Shift {double_encode['first_shift']} then Shift {double_encode['second_shift']}", highlight=True)
        pdf.key_value_row('Final Decoded Text', double_encode.get('final', 'N/A'))
    else:
        pdf.key_value_row('Double Encoding', 'No')
    pdf.ln(4)

    # ── Brute Force Rankings (top 5) ──────────────────────────────────────────
    all_results = result.get('all_results', [])
    if all_results:
        pdf.section_title('Top 5 Shift Candidates')
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(220, 220, 240)

        # Table header
        col_w = [20, 30, 130]
        pdf.cell(col_w[0], 7, 'Rank', fill=True, border=1, align='C')
        pdf.cell(col_w[1], 7, 'Shift', fill=True, border=1, align='C')
        pdf.cell(col_w[2], 7, 'Decoded Preview (first 60 chars)', fill=True, border=1, align='C')
        pdf.ln()

        pdf.set_font('Helvetica', '', 9)
        for i, r in enumerate(all_results[:5], start=1):
            preview = r['text'][:60].replace('\n', ' ')
            pdf.set_fill_color(255, 255, 255) if i % 2 == 0 else pdf.set_fill_color(250, 250, 255)
            pdf.cell(col_w[0], 6, f'#{i}  ({r["confidence"]:.1f}%)', fill=True, border=1, align='C')
            pdf.cell(col_w[1], 6, str(r['shift']), fill=True, border=1, align='C')
            pdf.cell(col_w[2], 6, preview, fill=True, border=1)
            pdf.ln()
        pdf.ln(4)

    # ── Letter Frequency Table ─────────────────────────────────────────────────
    pdf.section_title('Letter Frequency Analysis (Decoded Text)')
    observed = get_letter_frequencies(str(decoded))

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(220, 220, 240)
    cell_w = 10
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        pdf.cell(cell_w, 6, letter, fill=True, border=1, align='C')
    pdf.ln()

    pdf.set_font('Helvetica', '', 7)
    pdf.set_fill_color(255, 255, 255)
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        pct = observed.get(letter, 0.0) * 100
        pdf.cell(cell_w, 6, f'{pct:.1f}', border=1, align='C')
    pdf.ln()

    # English expected row
    pdf.set_font('Helvetica', 'I', 7)
    pdf.set_fill_color(240, 240, 255)
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        eng = ENGLISH_FREQ.get(letter, 0.0) * 100
        pdf.cell(cell_w, 6, f'{eng:.1f}', fill=True, border=1, align='C')
    pdf.ln(2)

    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, '  Row 1: Observed frequencies (%)  |  Row 2: Expected English frequencies (%)')
    pdf.ln(6)

    # ── Footer note ───────────────────────────────────────────────────────────
    pdf.set_text_color(150, 150, 150)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.multi_cell(0, 5, 'Generated by CipherShift — Built because manually testing 25 shifts is a war crime.\n'
                          'github.com/yourusername/caesar-cipher-analyzer')

    return bytes(pdf.output())
