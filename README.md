# 🔐 CipherShift — Caesar Cipher Analyzer & Breaker

> *"I got tired of manually testing all 25 Caesar shifts during CTFs at 3am, so I built this. You're welcome, future me."*
> — Mo, after his 47th cipher challenge

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-red?logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![CTF Ready](https://img.shields.io/badge/CTF-Ready-orange)
![Caffeine Powered](https://img.shields.io/badge/Powered%20By-Caffeine-brown)

---

## 🤔 Why Does This Exist?

Because every single CTF has that one Caesar cipher challenge sitting there like *"hehe, bet you won't try all 25 shifts."*

**Spoiler:** I did. Manually. For way too long. Then I wrote this tool so I never have to again.

CipherShift is a full-featured Caesar cipher analyzer built for CTF players, cryptography students, and anyone who's ever stared at `KHOOR ZRUOG` wondering if they needed more coffee or just a ROT3 decode.

*(It was ROT3. It's always ROT3.)*

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 **Encrypt / Decrypt** | Encode or decode with any known shift (0–25) |
| 🧠 **Auto-Crack** | Frequency analysis against English letter distribution |
| 📊 **Confidence Scoring** | 0–100% confidence score so you know how sure the tool is (spoiler: if it's below 40%, the answer is probably not English) |
| 💥 **Brute Force Mode** | All 25 shifts ranked by likelihood — because sometimes you just need to see them all |
| 🔁 **Double Encoding Detection** | Detects if someone thought encrypting twice was clever (it wasn't) |
| 🔄 **ROT13 Auto-Detection** | Instantly flags ROT13 so you can stop pretending it's a real cipher |
| 🟣 **Vigenère Detection** | Flags if the ciphertext might actually be Vigenère — so you know when to close this tab and open CyberChef |
| 📄 **PDF Export** | Export a full analysis report — great for writeups, even better for flexing on teammates |
| 📈 **Plotly Visualizations** | Interactive frequency charts because we're professionals |
| 🎨 **Clean Streamlit UI** | Dark-mode friendly, no PhD required |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- pip
- The will to live (optional but recommended)

### Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/caesar-cipher-analyzer.git
cd caesar-cipher-analyzer

# Install dependencies
pip install -r requirements.txt

# Download NLTK data (one-time setup)
python -c "import nltk; nltk.download('words')"

# Launch the app
streamlit run app.py
```

Then open your browser to `http://localhost:8501` and start cracking. 🔓

---

## 📁 Project Structure

```
caesar-cipher-analyzer/
├── app.py              # Streamlit UI — the pretty face of the operation
├── cli.py              # CLI tool — for when speed is everything
├── analyzer.py         # Caesar cipher core logic
├── vigenere.py         # Vigenère cracker (English + French frequency support)
├── frequency.py        # Letter frequency analysis & confidence scoring
├── double_encode.py    # Double encoding, ROT13 & Vigenère detection
├── report.py           # PDF report generation
├── requirements.txt    # Dependencies
└── README.md           # You are here
```

> **Cipher Support Roadmap**
> - [x] Caesar / ROT-N
> - [x] ROT13 detection
> - [x] Vigenère (English + French)
> - [ ] Substitution cipher
> - [ ] Rail fence / transposition
> - [ ] Base64 / encoding detection

---

## ⚡ CLI Usage

For CTF speed runs — no browser, no loading, just answers.

```bash
# Auto-detect && crack
python cli.py "KHOOR ZRUOG"

# Force cipher type
python cli.py "text" -c caesar
python cli.py "text" -c vigenere

# French Vigenère
python cli.py "text" -c vigenere --lang french

# Known Vigenère key
python cli.py "text" -c vigenere -k SECRETKEY

# Brute force all Caesar shifts
python cli.py "text" -m brute --top 5

# Encrypt / decrypt
python cli.py "Hello World" -m encrypt -s 13
python cli.py "Uryyb Jbeyq" -m decrypt -s 13
```

> The CLI uses `rich` for colored output and formatted tables. Falls back to plain text gracefully.

---

## 🛠️ How It Works

### Frequency Analysis
CipherShift compares the letter frequency distribution of the decoded text against the known statistical distribution of English (E, T, A, O, I, N, S, H, R...). The closer the match, the higher the confidence score.

> *"Is it English? The chi-squared statistic will tell you. The chi-squared statistic is never wrong. I've been wrong about the chi-squared statistic."*

### Confidence Scoring
Scores are calculated using a normalized chi-squared deviation from expected English frequencies:
- **80–100%** → Almost certainly correct
- **50–79%** → Probably right, worth checking
- **20–49%** → Maybe? Could be a different language or very short text
- **0–19%** → Not English, or you fed it binary. Either way, RIP.

### Double Encoding Detection
Checks whether decrypting once yields something that looks like it was *also* Caesar-encoded, and reports both shifts. Because yes, CTF authors do this. Yes, it's evil.

### Vigenère Detection
Uses the Index of Coincidence (IoC) to flag if the ciphertext likely isn't Caesar at all. If IoC ≈ 0.065, it's English Caesar. If IoC is way off, it's probably Vigenère — and that's a different tool for a different late night.

---

## 📸 Screenshots

*(Coming soon — once I finish fighting with Streamlit's column layout for the 4th time)*

---

## 🧪 Example Usage

**Input:**
```
KHOOR ZRUOG
```

**CipherShift Output:**
```
Best Shift:    3
Decoded:       HELLO WORLD
Confidence:    97.3%
ROT13:         No
Double Encode: No
Vigenère Flag: No
```

*"Wow. Revolutionary. Very impressed."* — Me, encountering this in a CTF at 2am

---

## 📦 Dependencies

```
streamlit
plotly
nltk
fpdf2
numpy
```

Full list with pinned versions in `requirements.txt`.

---

## 🤝 Contributing

Found a bug? Want to add a feature? Think the jokes in this README could be funnier?

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/actually-funny-jokes`
3. Commit your changes: `git commit -m "feat: add funnier jokes"`
4. Push and open a PR

All contributions welcome. Even the ones that are just fixing my typos.

---

## 📜 License

MIT — take it, use it, win CTFs with it. Just don't submit my code as your own homework. Or do. I'm a README, not a cop.

---

## 👤 Author

**Mo**
TAMUCC Computer Science — Cybersecurity Track
ICS Club Member | NCL Competitor | Professional Caesar Cipher Victim

> *"If cracking ciphers was an Olympic sport, I'd have a gold medal and severe sleep deprivation."*

---

*Built with Python, Streamlit, too much coffee, and a burning desire to never manually shift letters again.*

⭐ **Star this repo if it helped you crack a CTF cipher at an ungodly hour.**
