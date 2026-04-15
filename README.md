# 🔐 CipherShift: Caesar Cipher Analyzer & Breaker

> *"I got tired of manually testing all 25 Caesar shifts during CTFs at 3am, so I built this. You're welcome, future me."*
> - Mo, after his 47th cipher challenge

> *"Then I kept adding things. It's fine. Everything is fine."*
> - Mo, several CTFs later

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-red?logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![CTF Ready](https://img.shields.io/badge/CTF-Ready-orange)
![Caffeine Powered](https://img.shields.io/badge/Powered%20By-Caffeine-brown)

---

## 🤔 Why Does This Exist?

This started as a Caesar cipher tool. That's it. That was the whole plan.

I built it because every single CTF has that one Caesar cipher challenge sitting there like *"hehe, bet you won't try all 25 shifts."* **Spoiler:** I did. Manually. For way too long. So I wrote CipherShift with frequency analysis and honestly, I built it before I even fully understood what frequency analysis was. I just knew it worked. Here's the idea:

> Every language has a fingerprint. In English, the letter **E** shows up ~13% of the time, **T** ~9%, **A** ~8%, and so on. A Caesar cipher doesn't scramble *which* letters appear — it just slides them all by the same amount. Frequency analysis exploits this. Instead of trying all 25 shifts blindly, you look at the letter distribution, score each shift against expected English, and pick the winner. Statistics doing what brute force does, but smarter.

Once I had that working, I realized: I still had to open CyberChef every time a CTF threw a Vigenère at me. Or a Rail Fence. Or something that was just Base64 of Hex of ROT47 because the challenge author thought that was funny (it was not funny).

So I kept adding the ciphers and encodings I kept running into. CipherShift is still the same project — same name, same vibe — it just covers a lot more ground now. It was never planned as an "all-in-one toolkit." It became one because CTFs kept demanding it.

*(It was ROT3. It's always ROT3.)*

---

## ✨ Features

### 🔐 Ciphers

| Feature | Description |
|---|---|
| 🔒 **Caesar: Encrypt / Decrypt** | Encode or decode with any known shift (0–25) |
| 🧠 **Caesar: Auto-Crack** | Frequency analysis against English letter distribution |
| 💥 **Caesar: Brute Force** | All 25 shifts ranked by likelihood |
| 🔁 **Double Encoding Detection** | Detects if someone thought encrypting twice was clever (it wasn't) |
| 🔄 **ROT13 Auto-Detection** | Instantly flags ROT13 so you can stop pretending it's a real cipher |
| 🟣 **Vigenère Detection + Crack** | IoC-based detection, per-column frequency crack (English + French) |
| 🅰️ **Atbash Auto-Crack** | A↔Z, B↔Y — one shot, confidence scored |
| 🚂 **Rail Fence Brute Force** | Tries rails 2–10, ranks by confidence, redirects to CyberChef if stuck |
| 🟦 **Playfair Decode** | Decode with a known key; honest "can't auto-crack" redirect otherwise |

### 📦 Encodings

| Feature | Description |
|---|---|
| 🔢 **Binary** | 8-bit space-separated groups → ASCII |
| 🟩 **Hex** | Plain or space-separated hex strings |
| 🔵 **Base32** | Standard Base32 with padding handling |
| 🔴 **Base64** | Standard Base64 with auto-padding |
| 🔀 **ROT47** | Full printable ASCII rotation, confidence-gated |
| 🔗 **Cascade Detection** | Automatically unpeels nested layers (e.g. Base64 → Hex → text) |

### 📊 Everything Else

| Feature | Description |
|---|---|
| 📈 **Confidence Scoring** | 0–100% chi-squared based score on every result |
| 📄 **PDF Export** | Full analysis report — great for CTF writeups |
| 📈 **Plotly Visualizations** | Interactive frequency charts |
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
├── app.py                 # Streamlit UI: the pretty face of the operation
├── cli.py                 # CLI tool: for when speed is everything
├── analyzer.py            # Caesar cipher core logic
├── vigenere.py            # Vigenère cracker (English + French frequency support)
├── classic_ciphers.py     # Atbash, Rail Fence, Playfair
├── cipher_encodings.py    # Base64, Hex, Binary, ROT47, Base32 + cascade detection
├── frequency.py           # Letter frequency analysis & confidence scoring
├── double_encode.py       # Double encoding, ROT13 & Vigenère detection
├── report.py              # PDF report generation
├── requirements.txt       # Dependencies
└── README.md              # You are here
```

> **Cipher Support Roadmap**
> - [x] Caesar / ROT-N
> - [x] ROT13 detection
> - [x] Vigenère (English + French)
> - [x] Atbash
> - [x] Rail Fence
> - [x] Playfair (known key)
> - [x] Base64 / Base32 / Hex / Binary / ROT47 encoding detection
> - [x] Cascade / nested encoding detection
> - [ ] Substitution cipher
> - [ ] Playfair auto-crack (it's hard, okay)

---

## ⚡ CLI Usage

For CTF speed runs — no browser, no loading, just answers.

```bash
# Auto-detect && crack (checks encoding first, then cipher type)
python cli.py "KHOOR ZRUOG"

# Force cipher type
python cli.py "text" -c caesar
python cli.py "text" -c vigenere
python cli.py "text" -c atbash
python cli.py "text" -c railfence
python cli.py "text" -c railfence -r 3       # known rail count
python cli.py "text" -c playfair -k KEYWORD  # Playfair with known key
python cli.py "text" -c playfair             # will tell you to go to dcode.fr

# Encoding detection
python cli.py "SGVsbG8gV29ybGQ=" -c encoding        # auto-detect
python cli.py "48656c6c6f" -c encoding -e hex        # force specific encoding
# Cascade example: Base64 of Hex — it'll unpack both layers automatically

# French Vigenère
python cli.py "text" -c vigenere --lang french

# Known Vigenère key
python cli.py "text" -c vigenere -k SECRETKEY

# Brute force all Caesar shifts
python cli.py "text" -m brute --top 5

# Encrypt / decrypt Caesar
python cli.py "Hello World" -m encrypt -s 13
python cli.py "Uryyb Jbeyq" -m decrypt -s 13
```

> The CLI uses `rich` for colored output and formatted tables. Falls back to plain text gracefully if `rich` isn't installed.

---

## 🛠️ How It Works

### Frequency Analysis (Caesar)
CipherShift compares the letter frequency distribution of the decoded text against the known statistical distribution of English (E, T, A, O, I, N, S, H, R...). The closer the match, the higher the confidence score.

> *"Is it English? The chi-squared statistic will tell you. The chi-squared statistic is never wrong. I've been wrong about the chi-squared statistic."*

### Confidence Scoring
Scores are calculated using a normalized chi-squared deviation from expected English frequencies:
- **80–100%** → Almost certainly correct
- **50–79%** → Probably right, worth checking
- **20–49%** → Maybe? Could be a different language or very short text
- **0–19%** → Not English, or you fed it binary. Either way, RIP.

### Vigenère Detection & Cracking
Uses the Index of Coincidence (IoC) to detect polyalphabetic ciphers. If IoC ≈ 0.065, it's mono-alphabetic (Caesar). If IoC drops toward 0.038, it's likely Vigenère. Cracking uses IoC-based key length detection followed by per-column Caesar frequency analysis. Works best on 100+ character English or French ciphertext with key length ≤ 12.

### Rail Fence Brute Force
Tries every rail count from 2 to 10, decodes each, and ranks by confidence score. Short texts will give similar scores across rail counts — that's expected, not a bug.

### Atbash
It's its own inverse. One decode attempt, one confidence score, done. If confidence is low it'll tell you to try CyberChef. There's no shame in that.

### Playfair
Decode with a known key using standard 5×5 Polybius square rules (J merged with I). Auto-crack is not supported — it's computationally hard without a key and out of scope for this tool. The CLI will redirect you to dcode.fr rather than pretend otherwise.

### Cascade Encoding Detection
The encoding detector runs a cascade: Binary → Hex → Base32 → Base64 → ROT47. If a decode succeeds, it immediately checks whether the result is itself encoded — and keeps going until it hits plaintext or the recursion limit. So `Base64(Hex("Hello"))` comes out as `base64 → hex → Hello` automatically.

### Double Encoding Detection
Checks whether decrypting the ciphertext once yields something that looks like it was *also* Caesar-encoded, and reports both shifts. Because yes, CTF authors do this. Yes, it's evil.

---

## 📸 Screenshots

*(Coming soon, once I finish fighting with Streamlit's column layout for the 4th time)*

---

## 🧪 Example Usage

**Caesar:**
```
Input:    KHOOR ZRUOG
Shift:    3
Decoded:  HELLO WORLD
Conf:     97.3%
```

**Cascade Encoding:**
```
Input:    NDg2NTZjNmM2Zg==
Chain:    base64 → hex
Layers:   2
Decoded:  Hello
```

**Rail Fence:**
```
Input:    HOLELWRD O
Best:     2 rails
Decoded:  HELLO WORLD
Conf:     84.1%
```

---

## 📦 Dependencies

```
streamlit
plotly
nltk
fpdf2
numpy
rich
```

Full list with pinned versions in `requirements.txt`.

---

## 🤝 Contributing

Found a bug? Want to add a cipher? Think the jokes in this README could be funnier?

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/actually-funny-jokes`
3. Commit your changes: `git commit -m "feat: add funnier jokes"`
4. Push and open a PR

All contributions welcome. Even the ones that are just fixing my typos.

---

## 📜 License

MIT: take it, use it, win CTFs with it. Just don't submit my code as your own homework. Or do. I'm a README, not a cop.

---

## 👤 Author

**Mo**
TAMUCC Computer Science, Cybersecurity Track
ICS Club Member | NCL Competitor | Professional Cipher Victim

> *"This started as a Caesar cipher tool. It was supposed to stay that way. Then every CTF kept throwing something new at me, and here we are. I regret nothing."*

---

*Built with Python, Streamlit, too much coffee, and a burning desire to never manually decode anything again.*

⭐ **Star this repo if it saved you from opening CyberChef at 3am.**
