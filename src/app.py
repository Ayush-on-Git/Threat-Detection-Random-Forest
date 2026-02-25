import streamlit as st
import base64
import os
from threat_engine import analyze_url, extract_features
import time
import pandas as pd
from PIL import Image

# ===============================
# PAGE CONFIGURATION - WIDE LAYOUT
# ===============================
st.set_page_config(
    page_title="Advanced URL Threat Analyzer",
    page_icon="🛡️",
    layout="wide",  # Changed to wide for professional look
    initial_sidebar_state="expanded"
)

# ===============================
# HELPER: BASE64 IMAGE ENCODER
# ===============================
def get_base64_image(image_path):
    """Reads a local image and converts it to a base64 string for HTML embedding."""
    if os.path.exists(image_path):
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    return ""

# ===============================
# SESSION STATE INITIALIZATION
# ===============================
if "history" not in st.session_state:
    st.session_state.history = []
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

# ===============================
# ADVANCED CSS STYLING
# ===============================
st.markdown("""
<style>

/* ===== ANIMATED GRADIENT BACKGROUND ===== */
.stApp {
    background: linear-gradient(-45deg, #0f172a, #1e3a8a, #0f172a, #1e293b, #312e81);
    background-size: 400% 400%;
    animation: gradientBG 15s ease infinite;
    color: #e2e8f0;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}

@keyframes gradientBG {
    0% {background-position: 0% 50%;}
    50% {background-position: 100% 50%;}
    100% {background-position: 0% 50%;}
}

/* ===== PARTICLE BACKGROUND EFFECT ===== */
.particles {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 0;
    pointer-events: none;
}

.particle {
    position: absolute;
    background: rgba(56, 189, 248, 0.3);
    border-radius: 50%;
    animation: float 20s infinite;
}

@keyframes float {
    0%, 100% { transform: translateY(0px) translateX(0px); opacity: 0; }
    10% { opacity: 1; }
    90% { opacity: 1; }
    100% { transform: translateY(-1000px) translateX(100px); opacity: 0; }
}

/* ===== HERO SECTION ===== */
.hero-section {
    text-align: center;
    padding: 60px 20px 40px 20px;
    position: relative;
    z-index: 1;
}

.hero-title {
    font-size: 72px;
    font-weight: 900;
    background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 0 0 40px rgba(56, 189, 248, 0.5);
    margin-bottom: 15px;
    letter-spacing: -2px;
    animation: glow 3s ease-in-out infinite;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 20px;
}

@keyframes glow {
    0%, 100% { filter: drop-shadow(0 0 20px rgba(56, 189, 248, 0.5)); }
    50% { filter: drop-shadow(0 0 40px rgba(56, 189, 248, 0.8)); }
}

.hero-subtitle {
    font-size: 24px;
    color: #94a3b8;
    font-weight: 400;
    margin-bottom: 30px;
    letter-spacing: 0.5px;
}

/* ===== GLASS INPUT CONTAINER ===== */
[data-testid="stTextInput"] {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    padding: 40px 50px;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    margin-bottom: 20px;
}

/* ===== STREAMLIT INPUT FIELD CUSTOMIZATION ===== */
.stTextInput > div > div > input {
    font-size: 22px !important;
    padding: 12px 25px !important;
    background: rgba(255, 255, 255, 0) !important;
    color: #e2e8f0 !important;
    transition: all 0.3s ease !important;
    outline:none;
}

.stTextInput > div > div > input:focus {
    box-shadow: 0 0 20px rgba(56, 189, 248, 0.4) !important;
}

.stTextInput > div > div > input::placeholder {
    color: #64748b !important;
    font-size: 18px !important;
}

.stTextInput label p {
    font-size: 28px !important;
    font-weight: 600 !important;
    color: #cbd5e1 !important;
    margin-bottom: 12px !important;
}
            
[data-testid="stTextInputRootElement"]{
    border:3px solid transparent;
    height:max-content;
    border-radius:25px;
}

[data-testid="stTextInputRootElement"]:focus-within{
    border:3px solid #47b3f8;
}

/* ===== SCAN BUTTON STYLING ===== */
.stButton > button {
    width: 100%;
    font-size: 22px !important;
    font-weight: 700 !important;
    padding: 22px 40px !important;
    background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%) !important;
    border: none !important;
    border-radius: 15px !important;
    color: white !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 10px 30px rgba(59, 130, 246, 0.4) !important;
    margin-top: 25px !important;
}

.stButton > button:hover {
    transform: translateY(-3px) scale(1.02) !important;
    box-shadow: 0 15px 40px rgba(59, 130, 246, 0.6) !important;
    background: linear-gradient(135deg, #4f46e5 0%, #9333ea 100%) !important;
}

.stButton > button:active {
    transform: translateY(-1px) scale(1.01) !important;
}

/* ===== GLASS REPORT CARD ===== */
.report-card {
    background: rgba(255, 255, 255, 0.06);
    backdrop-filter: blur(25px);
    -webkit-backdrop-filter: blur(25px);
    padding: 50px 60px;
    border-radius: 30px;
    border: 2px solid rgba(255, 255, 255, 0.12);
    box-shadow: 0 8px 40px rgba(0, 0, 0, 0.4);
    max-width: 1100px;
    margin: 50px auto;
    position: relative;
    z-index: 1;
}

.report-card.high-risk {
    border: 3px solid #ef4444;
    box-shadow: 0 0 50px rgba(239, 68, 68, 0.6), 0 8px 40px rgba(0, 0, 0, 0.4);
    animation: dangerPulse 2s infinite alternate;
}

@keyframes dangerPulse {
    from { box-shadow: 0 0 30px rgba(239, 68, 68, 0.5), 0 8px 40px rgba(0, 0, 0, 0.4); }
    to { box-shadow: 0 0 60px rgba(239, 68, 68, 0.8), 0 8px 40px rgba(0, 0, 0, 0.4); }
}

/* ===== SECTION HEADERS ===== */
.section-title {
    font-size: 32px;
    font-weight: 700;
    color: #38bdf8;
    margin: 30px 0 20px 0;
    text-shadow: 0 0 15px rgba(56, 189, 248, 0.5);
}

/* ===== METRIC CARDS ===== */
.metric-card {
    background: rgba(255, 255, 255, 0.08);
    padding: 25px;
    border-radius: 15px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    text-align: center;
}

.metric-label {
    font-size: 16px;
    color: #94a3b8;
    margin-bottom: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-value {
    font-size: 36px;
    font-weight: 800;
    color: #e2e8f0;
}

/* ===== THREAT METER ===== */
.meter-container {
    position: relative;
    width: 400px;
    height: 400px;
    margin: 30px auto;
}

.meter-circle {
    transform: rotate(-90deg);
}

.meter-bg {
    fill: none;
    stroke: rgba(30, 41, 59, 0.8);
    stroke-width: 28;
}

.meter-fill {
    fill: none;
    stroke-width: 28;
    stroke-linecap: round;
    stroke-dasharray: 1100;
    stroke-dashoffset: 1100;
    animation: fillAnimation 2.5s cubic-bezier(0.4, 0, 0.2, 1) forwards;
    filter: drop-shadow(0px 0px 20px currentColor);
}

.meter-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}

.meter-score {
    font-size: 72px;
    font-weight: 900;
    line-height: 1;
    text-shadow: 0 0 30px currentColor;
}

.meter-label {
    font-size: 20px;
    color: #94a3b8;
    margin-top: 10px;
}

/* ===== CUSTOM CONFIDENCE BAR ===== */
.confidence-container {
    margin: 30px 0;
}

.confidence-bar-wrapper {
    width: 100%;
    height: 35px;
    background: rgba(30, 41, 59, 0.6);
    border-radius: 20px;
    overflow: hidden;
    position: relative;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.confidence-bar {
    height: 100%;
    background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
    border-radius: 20px;
    animation: growBar 2s cubic-bezier(0.4, 0, 0.2, 1) forwards;
    box-shadow: 0 0 20px rgba(59, 130, 246, 0.6);
    position: relative;
    overflow: hidden;
}

.confidence-bar::after {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
    animation: shimmer 2s infinite;
}

@keyframes growBar {
    from { width: 0%; }
}

@keyframes shimmer {
    0% { left: -100%; }
    100% { left: 100%; }
}

.confidence-text {
    font-size: 24px;
    font-weight: 700;
    color: #38bdf8;
    margin-top: 15px;
    text-align: center;
}

/* ===== RISK INDICATORS ===== */
.risk-indicator {
    background: rgba(255, 255, 255, 0.05);
    padding: 15px 20px;
    border-radius: 12px;
    margin: 12px 0;
    border-left: 4px solid #f59e0b;
    font-size: 17px;
    color: #cbd5e1;
}

/* ===== THREAT BREAKDOWN BARS ===== */
.threat-breakdown {
    margin: 30px 0;
}

.threat-bar-item {
    margin: 20px 0;
}

.threat-bar-label {
    display: flex;
    justify-content: space-between;
    font-size: 16px;
    color: #cbd5e1;
    margin-bottom: 8px;
}

.threat-bar-bg {
    width: 100%;
    height: 20px;
    background: rgba(30, 41, 59, 0.6);
    border-radius: 10px;
    overflow: hidden;
}

.threat-bar-fill {
    height: 100%;
    border-radius: 10px;
    animation: growBar 1.5s ease-out forwards;
    box-shadow: 0 0 15px currentColor;
}

/* ===== STATUS BADGES ===== */
.status-badge {
    display: inline-block;
    padding: 15px 35px;
    border-radius: 50px;
    font-size: 28px;
    font-weight: 800;
    margin: 20px 0;
    text-transform: uppercase;
    letter-spacing: 2px;
}

.badge-safe {
    background: linear-gradient(135deg, #10b981, #059669);
    color: white;
    box-shadow: 0 10px 30px rgba(16, 185, 129, 0.4);
}

.badge-malicious {
    background: linear-gradient(135deg, #ef4444, #dc2626);
    color: white;
    box-shadow: 0 10px 30px rgba(239, 68, 68, 0.4);
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
}

/* ===== PROGRESS BAR OVERRIDE ===== */
.stProgress > div > div > div {
    background: linear-gradient(90deg, #3b82f6, #8b5cf6) !important;
    height: 8px !important;
}

/* ===== EXPANDER STYLING ===== */
.streamlit-expanderHeader {
    background: rgba(255, 255, 255, 0.05) !important;
    border-radius: 12px !important;
    font-size: 18px !important;
    font-weight: 600 !important;
    color: #94a3b8 !important;
}

/* ===== HISTORY SECTION ===== */
.history-item {
    background: rgba(255, 255, 255, 0.05);
    padding: 20px;
    border-radius: 12px;
    margin: 12px 0;
    border-left: 4px solid;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 17px;
}

.history-item.high { border-left-color: #ef4444; }
.history-item.medium { border-left-color: #f59e0b; }
.history-item.low { border-left-color: #10b981; }

/* ===== TERMINAL EFFECT ===== */
.terminal {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 20px;
    font-family: 'Courier New', monospace;
    color: #22c55e;
    font-size: 14px;
    margin: 20px 0;
}

.terminal-line {
    margin: 8px 0;
}

.terminal-cursor {
    animation: blink 1s infinite;
}

@keyframes blink {
    0%, 50% { opacity: 1; }
    51%, 100% { opacity: 0; }
}

/* ===== SIDEBAR ANALYTICS ===== */
[data-testid="stSidebar"] {
    background: rgba(15, 23, 42, 0.9) !important;
    backdrop-filter: blur(20px) !important;
    border-right: 1px solid rgba(255, 255, 255, 0.1) !important;
}

.sidebar-stat {
    background: rgba(255, 255, 255, 0.05);
    padding: 20px;
    border-radius: 12px;
    margin: 15px 0;
    text-align: center;
}

.sidebar-stat-value {
    font-size: 32px;
    font-weight: 800;
    color: #38bdf8;
}

.sidebar-stat-label {
    font-size: 14px;
    color: #94a3b8;
    margin-top: 8px;
}

/* ===== DATAFRAME STYLING ===== */
.stDataFrame {
    background: rgba(255, 255, 255, 0.05) !important;
    border-radius: 12px !important;
}

</style>
""", unsafe_allow_html=True)

# ===============================
# HERO SECTION
# ===============================
logo_base64 = get_base64_image("logo.png")
img_src = f"data:image/png;base64,{logo_base64}" if logo_base64 else ""

st.markdown(f"""
<div class="hero-section">
    <div class="hero-title">
            <img src="{img_src}" alt="logo-icon" width="80" style="vertical-align: middle;" />
            URL THREAT INTELLIGENCE
    </div>
    <div class="hero-subtitle">Advanced AI-Powered Cybersecurity Analysis Platform</div>
</div>
""", unsafe_allow_html=True)

# ===============================
# SIDEBAR ANALYTICS PANEL
# ===============================
with st.sidebar:
    st.markdown("# Analytics Dashboard")

    total_scans = len(st.session_state.history)
    high_risk_count = sum(
        1 for item in st.session_state.history if item["Risk"] == "HIGH")
    medium_risk_count = sum(
        1 for item in st.session_state.history if item["Risk"] == "MEDIUM")
    low_risk_count = sum(
        1 for item in st.session_state.history if item["Risk"] == "LOW")

    st.markdown(f"""
    <div class="sidebar-stat">
        <div class="sidebar-stat-value">{total_scans}</div>
        <div class="sidebar-stat-label">TOTAL SCANS</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="sidebar-stat">
        <div class="sidebar-stat-value" style="color: #ef4444;">{high_risk_count}</div>
        <div class="sidebar-stat-label">HIGH RISK</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="sidebar-stat">
        <div class="sidebar-stat-value" style="color: #f59e0b;">{medium_risk_count}</div>
        <div class="sidebar-stat-label">MEDIUM RISK</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="sidebar-stat">
        <div class="sidebar-stat-value" style="color: #10b981;">{low_risk_count}</div>
        <div class="sidebar-stat-label">LOW RISK</div>
    </div>
    """, unsafe_allow_html=True)


# ===============================
# GLASS INPUT CONTAINER
# ===============================

url = st.text_input(
    "Enter URL to Analyze:",
    placeholder="https://example.com",
    key="url_input",
)

# ===============================
# ANIMATED THREAT METER FUNCTION
# ===============================


def animated_threat_meter(score, risk_level):
    color = "#10b981" if risk_level == "LOW" else \
            "#f59e0b" if risk_level == "MEDIUM" else \
            "#ef4444"

    dashoffset = 1100 - (score / 100) * 1100

    st.markdown(f"""
    <style>
    @keyframes fillAnimation {{
        to {{ stroke-dashoffset: {dashoffset}; }}
    }}
    </style>
    
    <div class="meter-container">
        <svg width="400" height="400" class="meter-circle">
            <circle cx="200" cy="200" r="175" class="meter-bg"/>
            <circle cx="200" cy="200" r="175"
                class="meter-fill"
                stroke="{color}"
                style="color: {color};"/>
        </svg>
        <div class="meter-text">
            <div class="meter-score" style="color:{color};">{score}</div>
            <div class="meter-label">THREAT SCORE</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ===============================
# CUSTOM CONFIDENCE BAR
# ===============================


def custom_confidence_bar(confidence):
    st.markdown(f"""
    <div class="confidence-container">
        <div class="confidence-bar-wrapper">
            <div class="confidence-bar" style="width: {confidence}%;"></div>
        </div>
        <div class="confidence-text">{confidence}% Model Confidence</div>
    </div>
    """, unsafe_allow_html=True)

# ===============================
# THREAT BREAKDOWN BARS
# ===============================


def threat_breakdown(features_dict):
    st.markdown('<div class="section-title">🔍 Threat Factor Analysis</div>',
                unsafe_allow_html=True)
    st.markdown('<div class="threat-breakdown">', unsafe_allow_html=True)

    # Select key features for visualization
    key_features = {
        "URL Length": min(features_dict.get("url_length", 0) / 100 * 100, 100),
        "Suspicious Characters": features_dict.get("nb_dots", 0) * 10,
        "Domain Complexity": min(features_dict.get("length_hostname", 0) / 50 * 100, 100),
        "Security Indicators": 100 - (features_dict.get("https_token", 0) * 100)
    }

    colors = ["#3b82f6", "#8b5cf6", "#ec4899", "#f59e0b"]

    for idx, (label, value) in enumerate(key_features.items()):
        color = colors[idx % len(colors)]
        st.markdown(f"""
        <div class="threat-bar-item">
            <div class="threat-bar-label">
                <span>{label}</span>
                <span>{int(value)}%</span>
            </div>
            <div class="threat-bar-bg">
                <div class="threat-bar-fill" 
                     style="width: {value}%; background: {color}; color: {color};"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


# ===============================
# SCAN BUTTON & ANALYSIS
# ===============================
if st.button("SCAN URL"):

    if url:

        terminal_placeholder = st.empty()

        terminal_steps = [
            ">>> Initializing threat analysis engine...",
            ">>> Extracting URL features...",
            ">>> Running ML model prediction...",
            ">>> Analyzing domain reputation...",
            ">>> Generating threat report...",
            ">>> Analysis complete ✓"
        ]

        for step in terminal_steps:
            terminal_placeholder.markdown(
                f'<div class="terminal-line">{step}<span class="terminal-cursor">_</span></div>', unsafe_allow_html=True)
            time.sleep(0.3)

        st.markdown('</div>', unsafe_allow_html=True)

        # Progress bar
        progress = st.progress(0)
        for i in range(100):
            time.sleep(0.01)
            progress.progress(i + 1)

        # Get analysis result
        result = analyze_url(url)
        progress.empty()

        # Calculate confidence
        confidence = abs(result["probability"] - 0.5) * 200
        confidence = round(confidence, 2)

        # Add to history
        st.session_state.history.append({
            "URL": result["domain"],
            "Risk": result["risk_level"],
            "Score": result["threat_score"]
        })

        st.markdown('</div>', unsafe_allow_html=True)  # Close input container

        # ===============================
        # ANALYSIS REPORT CARD
        # ===============================

        # Status Badge
        if result["prediction"] == 1:
            st.markdown(
                '<div class="status-badge badge-malicious">🚨 MALICIOUS DETECTED</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                '<div class="status-badge badge-safe">✅ URL IS SAFE</div>', unsafe_allow_html=True)

        # Metrics Row
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Domain</div>
                <div class="metric-value" style="font-size: 24px;">{result["domain"][:30]}</div>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            risk_color = "#10b981" if result["risk_level"] == "LOW" else \
                "#f59e0b" if result["risk_level"] == "MEDIUM" else "#ef4444"
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value" style="color: {risk_color};">{result["risk_level"]}</div>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Threat Score</div>
                <div class="metric-value">{result["threat_score"]}/100</div>
            </div>
            """, unsafe_allow_html=True)

        # Threat Meter
        st.markdown(
            '<div class="section-title">🎯 Threat Assessment</div>', unsafe_allow_html=True)
        animated_threat_meter(result["threat_score"], result["risk_level"])

        # Custom Confidence Bar
        st.markdown(
            '<div class="section-title">🧠 Model Confidence</div>', unsafe_allow_html=True)
        custom_confidence_bar(confidence)

        # Threat Breakdown
        features = extract_features(result["domain"])
        threat_breakdown(features)

        # Risk Indicators
        st.markdown(
            '<div class="section-title">⚠️ Risk Indicators</div>', unsafe_allow_html=True)
        for reason in result["reasons"]:
            st.markdown(
                f'<div class="risk-indicator">• {reason}</div>', unsafe_allow_html=True)

        # Technical Analysis Expander
        with st.expander("🔬 Technical Analysis - For Experts Only"):
            st.markdown("### Feature Extraction Results")
            df = pd.DataFrame(features.items(), columns=["Feature", "Value"])
            st.dataframe(df, width="stretch")

            st.markdown("### Feature Distribution")
            st.bar_chart(df.set_index("Feature"))

        st.markdown('</div>', unsafe_allow_html=True)  # Close report card

    else:
        st.markdown('</div>', unsafe_allow_html=True)  # Close input container
        st.warning("⚠️ Please enter a URL to analyze")

else:
    # Close input container if no scan
    st.markdown('</div>', unsafe_allow_html=True)

# ===============================
# SCAN HISTORY SECTION
# ===============================
if st.session_state.history:

    st.markdown('<div class="section-title" style="text-align: center; margin-top: 60px;">📜 Scan History</div>',
                unsafe_allow_html=True)

    history_df = pd.DataFrame(st.session_state.history)

    # Display history items
    for index, row in history_df.iterrows():
        risk_class = row["Risk"].lower()
        arrow = "🔴" if row["Risk"] == "HIGH" else "🟡" if row["Risk"] == "MEDIUM" else "🟢"

        st.markdown(f"""
        <div class="history-item {risk_class}">
            <div>
                <strong>{arrow} {row['URL'][:60]}</strong>
                <br>
                <small style="color: #64748b;">Risk: {row['Risk']} | Score: {row['Score']}/100</small>
            </div>
        </div>
        """, unsafe_allow_html=True)