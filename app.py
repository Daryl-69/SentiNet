"""SentiNet web interface. Start with:  python -m sentinet app   (or: streamlit run app.py)

Runs fully offline: no cloud calls, no external APIs.
"""
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

st.set_page_config(page_title="SentiNet · Attack Forecasting", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.block-container{padding-top:3.2rem}
div[data-testid="stMetricValue"]{font-size:1.55rem}
</style>""", unsafe_allow_html=True)

pages = [
    st.Page(str(ROOT / "ui" / "live.py"), title="Live monitor", icon="📡", default=True),
    st.Page(str(ROOT / "ui" / "analyse.py"), title="Analyse a capture", icon="🔎"),
]
st.navigation(pages).run()
