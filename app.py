"""
app.py — CipherShift Streamlit UI
The pretty face on top of a lot of frequency analysis math.

If you're reading this at 2am during a CTF, you're in the right place.
Welcome. The coffee is metaphorical but the cipher cracking is very real.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from analyzer import encrypt, decrypt, auto_crack, brute_force, caesar_shift
from frequency import get_letter_frequencies, ENGLISH_FREQ
from double_encode import get_detection_summary
from report import generate_report


# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherShift",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00d4ff, #7b2ff7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #888;
        font-size: 0.95rem;
        margin-bottom: 1.5rem;
    }
    .confidence-badge {
        padding: 0.3rem 0.8rem;
        border-radius: 12px;
        font-weight: bold;
        display: inline-block;
    }
    .metric-card {
        background: #1e1e2e;
        border: 1px solid #333;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .flag-detected {
        color: #ff4b4b;
        font-weight: bold;
    }
    .flag-clear {
        color: #21c45d;
    }
    .stTextArea textarea {
        font-family: 'Courier New', monospace;
    }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 CipherShift")
    st.markdown("*Caesar Cipher Analyzer & Breaker*")
    st.divider()

    mode = st.radio(
        "**Mode**",
        ["🧠 Auto-Crack", "🔒 Encrypt / Decrypt", "💥 Brute Force"],
        help="Auto-Crack uses frequency analysis. Brute Force shows all 25 shifts ranked."
    )

    st.divider()
    st.markdown("#### ℹ️ About")
    st.markdown("""
    Built by **Mo** @ TAMUCC  
    ICS Club | NCL Competitor  
    
    *"I got tired of testing 25 shifts manually in CTFs so I automated the whole thing. 
    You're welcome."*
    """)
    st.divider()
    st.caption("v1.0 | MIT License | github.com/yourusername/caesar-cipher-analyzer")


# ── Main Header ───────────────────────────────────────────────────────────────
st.markdown('<div class="main-header">🔐 CipherShift</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Caesar Cipher Analyzer & Breaker — Built for CTF players, by a CTF player who was <em>very tired</em> of doing this by hand.</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# MODE: AUTO-CRACK
# ─────────────────────────────────────────────────────────────────────────────
if mode == "🧠 Auto-Crack":
    st.subheader("🧠 Auto-Crack via Frequency Analysis")
    st.caption("Paste your ciphertext and let statistics do what you're too tired to do manually.")

    ciphertext = st.text_area(
        "Ciphertext",
        placeholder="Paste your Caesar-encrypted text here... KHOOR ZRUOG, ZLWK DQRWKHU BHQ of mystery",
        height=150,
        key="autocrack_input"
    )

    col_btn, col_space = st.columns([1, 4])
    with col_btn:
        run_crack = st.button("🚀 Crack It", type="primary", use_container_width=True)

    if run_crack and ciphertext.strip():
        with st.spinner("Running frequency analysis... (it's fast, I promise)"):
            result = auto_crack(ciphertext)

        # ── Results Header ────────────────────────────────────────────────────
        st.divider()
        st.subheader("📊 Analysis Results")

        conf = result['confidence']
        conf_color = "#21c45d" if conf >= 70 else ("#f59e0b" if conf >= 40 else "#ef4444")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Best Shift", f"ROT-{result['shift']}")
        col2.metric("Confidence", f"{conf:.1f}%")
        col3.metric("ROT13?", "YES 🔄" if result['is_rot13'] else "No")
        col4.metric("Vigenère?", "⚠️ Possible" if result['vigenere_flag'] else "No")

        # Confidence bar
        st.markdown(f"""
        <div style="background:#222; border-radius:8px; padding:8px 12px; margin:8px 0;">
            <div style="font-size:0.8rem; color:#aaa; margin-bottom:4px;">Confidence Score</div>
            <div style="background:#333; border-radius:6px; height:18px; width:100%;">
                <div style="background:{conf_color}; width:{conf:.0f}%; height:100%; border-radius:6px; transition:width 0.5s;"></div>
            </div>
            <div style="font-size:0.75rem; color:{conf_color}; margin-top:4px;">{conf:.1f}% — {'Very High' if conf>=80 else 'Medium' if conf>=50 else 'Low' if conf>=25 else 'Very Low'}</div>
        </div>
        """, unsafe_allow_html=True)

        # ── Decoded text ──────────────────────────────────────────────────────
        st.markdown("**🔓 Decoded Text**")
        st.code(result['decoded'], language=None)

        # ── Detection Flags ────────────────────────────────────────────────────
        st.subheader("🚩 Detection Flags")
        fcol1, fcol2, fcol3 = st.columns(3)

        with fcol1:
            if result['is_rot13']:
                st.error("🔄 **ROT13 Detected**\nShift = 13. Classic obfuscation. Not impressed.")
            else:
                st.success("✅ ROT13: Clear")

        with fcol2:
            if result['vigenere_flag']:
                st.warning("🟣 **Vigenère Suspected**\nIoC too low for Caesar. Try a polyalphabetic tool — this one can't help you here.")
            else:
                st.success("✅ Vigenère: Clear")

        with fcol3:
            de = result.get('double_encode')
            if de and de.get('detected'):
                st.error(f"🔁 **Double Encoding Detected!**\nShift {de['first_shift']} → Shift {de['second_shift']}\nFinal: `{de['final'][:40]}...`")
            else:
                st.success("✅ Double Encode: Clear")

        # ── Frequency Chart ───────────────────────────────────────────────────
        st.subheader("📈 Letter Frequency Analysis")
        letters = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        observed = get_letter_frequencies(result['decoded'])

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=letters,
            y=[observed.get(l, 0) * 100 for l in letters],
            name='Decoded Text',
            marker_color='#00d4ff',
            opacity=0.85
        ))
        fig.add_trace(go.Scatter(
            x=letters,
            y=[ENGLISH_FREQ.get(l, 0) * 100 for l in letters],
            mode='lines+markers',
            name='Expected English',
            line=dict(color='#ff6b6b', width=2, dash='dash'),
            marker=dict(size=5)
        ))
        fig.update_layout(
            title='Letter Frequency: Decoded Text vs Expected English',
            xaxis_title='Letter',
            yaxis_title='Frequency (%)',
            plot_bgcolor='#0e1117',
            paper_bgcolor='#0e1117',
            font_color='#fafafa',
            legend=dict(bgcolor='#1a1a2e'),
            bargap=0.2
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── PDF Export ────────────────────────────────────────────────────────
        st.divider()
        st.subheader("📄 Export Report")
        st.caption("Generate a professional PDF report — great for CTF writeups or just sending to teammates to prove you solved it.")

        if st.button("📥 Generate PDF Report"):
            with st.spinner("Generating report... (making it look professional)"):
                pdf_bytes = generate_report(ciphertext, result, mode="Auto-Crack")
            st.download_button(
                label="⬇️ Download Analysis Report (PDF)",
                data=pdf_bytes,
                file_name=f"ciphershift_report_shift{result['shift']}.pdf",
                mime="application/pdf"
            )
            st.success("Report ready! Download above. ✅")

    elif run_crack and not ciphertext.strip():
        st.warning("⚠️ Please enter some ciphertext first. (The tool is powerful, but it can't crack nothing.)")


# ─────────────────────────────────────────────────────────────────────────────
# MODE: ENCRYPT / DECRYPT
# ─────────────────────────────────────────────────────────────────────────────
elif mode == "🔒 Encrypt / Decrypt":
    st.subheader("🔒 Encrypt / Decrypt with Known Shift")
    st.caption("When you already know the shift. Showing off to teammates, generating test cases, or actually doing crypto homework.")

    col_txt, col_opt = st.columns([2, 1])
    with col_txt:
        text_input = st.text_area("Input Text", placeholder="Enter plaintext or ciphertext...", height=150)
    with col_opt:
        operation = st.radio("Operation", ["Encrypt", "Decrypt"])
        shift_val = st.slider("Shift Value", min_value=0, max_value=25, value=13,
                               help="ROT13 = 13. ROT-anything-else = your problem.")
        st.caption(f"ROT{shift_val}" + (" — ROT13, the classic!" if shift_val == 13 else ""))

    if st.button("⚡ Apply Shift", type="primary"):
        if text_input.strip():
            if operation == "Encrypt":
                output = encrypt(text_input, shift_val)
                label = f"🔒 Encrypted (Shift +{shift_val})"
            else:
                output = decrypt(text_input, shift_val)
                label = f"🔓 Decrypted (Shift -{shift_val})"

            st.markdown(f"**{label}**")
            st.code(output, language=None)

            # Quick frequency viz of output
            letters = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
            freqs = get_letter_frequencies(output)
            fig = px.bar(
                x=letters, y=[freqs.get(l, 0) * 100 for l in letters],
                labels={'x': 'Letter', 'y': 'Frequency (%)'},
                title=f'Letter Distribution of Output',
                color=[freqs.get(l, 0) for l in letters],
                color_continuous_scale='Blues'
            )
            fig.update_layout(
                plot_bgcolor='#0e1117', paper_bgcolor='#0e1117',
                font_color='#fafafa', showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("⚠️ Please enter some text first.")


# ─────────────────────────────────────────────────────────────────────────────
# MODE: BRUTE FORCE
# ─────────────────────────────────────────────────────────────────────────────
elif mode == "💥 Brute Force":
    st.subheader("💥 Brute Force — All 25 Shifts")
    st.caption("When frequency analysis gives up and you need to eyeball all 25 options yourself. We've all been there.")

    ciphertext_bf = st.text_area(
        "Ciphertext",
        placeholder="Paste ciphertext to brute force...",
        height=150,
        key="bruteforce_input"
    )

    col1, col2 = st.columns([1, 3])
    with col1:
        run_bf = st.button("💥 Run Brute Force", type="primary", use_container_width=True)
    with col2:
        top_n = st.slider("Show top N results", min_value=5, max_value=26, value=10)

    if run_bf and ciphertext_bf.strip():
        with st.spinner("Testing all 25 shifts... (it's really fast, I just like the spinner)"):
            results = brute_force(ciphertext_bf)

        st.divider()
        st.subheader(f"📋 All Shifts Ranked by Confidence (showing top {top_n})")

        # Confidence overview chart
        all_shifts = [r['shift'] for r in results]
        all_confs = [r['confidence'] for r in results]
        fig = go.Figure(go.Bar(
            x=[f"ROT{s}" for s in all_shifts],
            y=all_confs,
            marker_color=['#00d4ff' if i == 0 else '#444' for i in range(len(results))],
            text=[f"{c:.1f}%" for c in all_confs],
            textposition='outside'
        ))
        fig.update_layout(
            title='All 25 Shifts — Confidence Scores',
            xaxis_title='Shift (ROT-N)',
            yaxis_title='Confidence (%)',
            plot_bgcolor='#0e1117',
            paper_bgcolor='#0e1117',
            font_color='#fafafa',
            xaxis_tickangle=-45,
            yaxis_range=[0, 110]
        )
        st.plotly_chart(fig, use_container_width=True)

        # Results table
        for i, r in enumerate(results[:top_n]):
            rank_icon = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else f"#{i+1}"
            conf = r['confidence']
            conf_emoji = "🟢" if conf >= 70 else "🟡" if conf >= 40 else "🔴"

            with st.expander(f"{rank_icon} ROT-{r['shift']} — Confidence: {conf:.1f}% {conf_emoji}"):
                st.code(r['text'], language=None)
                if i == 0:
                    st.caption("⬆️ Highest confidence — most likely correct.")
                    if conf < 40:
                        st.caption("⚠️ Low confidence even for top result. May not be Caesar, or text is very short.")

        # Export
        st.divider()
        if st.button("📄 Export Brute Force Report (PDF)"):
            best = results[0]
            report_result = {
                'shift': best['shift'],
                'decoded': best['text'],
                'confidence': best['confidence'],
                'all_results': results,
                'is_rot13': best['shift'] == 13,
                'double_encode': None,
                'vigenere_flag': False
            }
            pdf_bytes = generate_report(ciphertext_bf, report_result, mode="Brute Force")
            st.download_button(
                label="⬇️ Download Brute Force Report (PDF)",
                data=pdf_bytes,
                file_name="ciphershift_bruteforce_report.pdf",
                mime="application/pdf"
            )

    elif run_bf and not ciphertext_bf.strip():
        st.warning("⚠️ Need ciphertext to brute force. (The tool is powerful, but not psychic.)")
