# pages/1_Analyze_Data.py
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import pickle
import plotly.express as px
import requests
import os
import json
from datetime import datetime
from sqlalchemy import create_engine

# Optional imports for GeoIP
try:
    import geoip2.database
except Exception:
    geoip2 = None

# --- Paths ---
# This is where the files will be *saved* locally on the server
MODEL_PATH = "models/threat_model.pkl"
PREPROC_PATH = "data/processed/processed_data.pkl" 
BUNDLED_GEO_PATH = "geo/GeoLite2-City.mmdb"

# --- !! PASTE YOUR 3 GITHUB RELEASE LINKS HERE !! ---
GEO_DOWNLOAD_URL = "https://github.com/Rhythmz7/AI-Based-Cyber-Security-Threats-Prediction/releases/download/Projectassets/GeoLite2-City.mmdb"
MODEL_DOWNLOAD_URL = "https://github.com/Rhythmz7/AI-Based-Cyber-Security-Threats-Prediction/releases/download/Projectassets/threat_model.pkl"
PREPROC_DOWNLOAD_URL = "https://github.com/Rhythmz7/AI-Based-Cyber-Security-Threats-Prediction/releases/download/Projectassets/processed_data.pkl"
# --- !! --------------------------------------- !! ---


# --- Helper function to download files ---
def download_file(url, local_path):
    """Downloads a file from a URL to a local path."""
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    if not os.path.exists(local_path):
        st.info(f"Downloading file: {os.path.basename(local_path)}...")
        try:
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                with open(local_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): 
                        f.write(chunk)
            st.info(f"Download complete: {os.path.basename(local_path)}")
        except Exception as e:
            st.error(f"Failed to download {local_path}: {e}")
            return False
    return True

# --- Caching and Asset Loading (NOW WITH DOWNLOADS) ---
@st.cache_resource
def load_assets(model_url, model_path, preproc_url, preproc_path):
    model = None
    scaler = None
    feature_names = None
    attack_map = {}
    load_err = None

    # 1. Download model and preprocessor if they don't exist
    model_ok = download_file(model_url, model_path)
    preproc_ok = download_file(preproc_url, preproc_path)

    if not (model_ok and preproc_ok):
        load_err = "Failed to download critical model or preprocessor files."
        return None, None, None, None, load_err

    # 2. Load the model
    try:
        model = joblib.load(model_path)
    except Exception as e:
        load_err = f"Error loading model: {e}"
        return None, None, None, None, load_err

    # 3. Load the preprocessor
    try:
        with open(preproc_path, "rb") as f:
            pdata = pickle.load(f)
        scaler = pdata.get("scaler")
        feature_names = pdata.get("feature_names")
        attack_map_raw = pdata.get("attack_types", {})
        attack_map = {v: k for k, v in attack_map_raw.items()}
    except Exception as e:
        load_err = f"Error loading preprocessor: {e}"
        return None, None, None, None, load_err

    return model, scaler, feature_names, attack_map, None

@st.cache_resource
def get_analysis_engine():
    # Build a new SQLAlchemy engine string from the Streamlit secrets
    try:
        db_user = st.secrets["db_user"]
        db_pass = st.secrets["db_pass"]
        db_host = st.secrets["db_host"]
        db_port = st.secrets["db_port"]
        db_name = st.secrets["db_name"]
        
        engine_url = f"postgresql+psycopg2://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
        
        return create_engine(engine_url)
    except Exception as e:
        st.error(f"Error creating analysis engine: {e}")
        return None

analysis_engine = get_analysis_engine()

# --- GeoIP Reader (NOW WITH DOWNLOAD) ---
@st.cache_resource
def load_geo_reader(local_path: str, download_url: str):
    # 1. Download file if it doesn't exist
    geo_ok = download_file(download_url, local_path)
    if not geo_ok:
        return None
    
    # 2. Now that file exists (or did already), load it.
    if geoip2 is None:
        st.warning("geoip2 library not installed.")
        return None
    
    try:
        reader = geoip2.database.Reader(local_path)
        return reader
    except Exception as e:
        st.error(f"Failed to load GeoIP database from {local_path}: {e}")
        return None

# --- GeoIP Helpers ---
def ip_to_latlon_pseudo(ip: str):
    try:
        parts = [int(p) for p in str(ip).split(".") if p.isdigit()]
        if len(parts) >= 4:
            a,b,c,d = parts[:4]
            lat = ((a * 256 + b) % 140) - 60 + (c / 256.0)
            lon = ((c * 256 + d) % 340) - 170 + (b / 256.0)
            return float(lat), float(lon)
    except Exception:
        pass
    h = abs(hash(str(ip))) % (360 * 1000)
    lat = (h % 140000)/1000.0 - 60
    lon = ((h // 140000) % 340000)/1000.0 - 170
    return lat, lon

def ip_to_geo(reader, ip: str):
    if reader:
        try:
            rec = reader.city(ip)
            return float(rec.location.latitude or 0.0), float(rec.location.longitude or 0.0)
        except Exception:
            pass
    return ip_to_latlon_pseudo(ip)

# --- Data Loading & Inference ---
def load_dataframe(uploaded_file):
    try:
        name = uploaded_file.name.lower()
        if name.endswith(".csv"):
            return pd.read_csv(uploaded_file, encoding="latin1", low_memory=False)
        if name.endswith(".json"):
            return pd.read_json(uploaded_file, orient="records")
        if name.endswith(".parquet"):
            return pd.read_parquet(uploaded_file)
        st.error("Unsupported file type. Use CSV/JSON/Parquet.")
    except Exception as e:
        st.error(f"Error reading file: {e}")
    return None

def preprocess_for_model(df, scaler, feature_names):
    if scaler is None or feature_names is None:
        st.error("Model or preprocessor not loaded.")
        return None
    df_proc = df.copy()
    df_proc.columns = df_proc.columns.str.strip()
    df_proc = df_proc.replace([np.inf, -np.inf], np.nan)
    
    if not feature_names:
        st.error("Feature names list is empty. Preprocessor file might be corrupt.")
        return None
        
    missing_cols = [c for c in feature_names if c not in df_proc.columns]
    for c in missing_cols:
        df_proc[c] = 0
    
    # Ensure columns are in the correct order
    X_df = df_proc[feature_names]
    X_df = X_df.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    try:
        Xs = scaler.transform(X_df.values)
        return Xs
    except Exception as e:
        st.error(f"Scaling error: {e}. Check if uploaded data matches training data structure.")
        return None

def run_inference(df, model, scaler, feature_names, attack_map):
    Xs = preprocess_for_model(df, scaler, feature_names)
    if Xs is None:
        return pd.DataFrame()
    preds = model.predict(Xs)
    labels = [attack_map.get(p, str(p)) for p in preds]
    out = df.copy()
    out["Predicted_Threat_ID"] = preds
    out["Predicted_Threat_Type"] = labels
    out["_analyzed_at"] = datetime.now().isoformat()
    return out

def threat_severity_score(threat_name: str):
    t = str(threat_name).lower()
    if t in ("benign", "0", "normal"): return 0
    if "ransom" in t: return 10
    if "ddos" in t: return 9
    if "bot" in t or "malware" in t: return 8
    if "sql injection" in t or "xss" in t: return 7
    if "scan" in t: return 5
    if "phish" in t: return 6
    return 4

def compute_overall_risk(results_df):
    if results_df is None or results_df.empty: return 0.0
    scores = [threat_severity_score(x) for x in results_df["Predicted_Threat_Type"].astype(str)]
    avg = float(np.mean(scores))
    return round((avg / 10.0) * 100.0, 2)

def save_analysis_to_db(results_df, source_name):
    """Saves analysis results to the user_analysis.db"""
    if results_df is None or results_df.empty:
        return 0
    
    df_to_save = results_df.copy()
    df_to_save['analysis_source'] = source_name
    
    try:
        df_to_save.to_sql(
            "analysis_history",  # Table name
            analysis_engine,
            if_exists="append",
            index=False
        )
        return len(df_to_save)
    except Exception as e:
        st.error(f"Failed to save to user_analysis.db: {e}")
        return 0
        
# --- Page UI ---
st.set_page_config(page_title="Analyze Datasets", layout="wide")
st.title("🔬 Analyze Offline Datasets")
st.write("Upload local files (CSV, JSON, Parquet) or fetch from an API to run inference using the pre-trained model.")

# --- Load Model (NOW WITH DOWNLOADS) ---
ml_model, scaler, feature_names, attack_map, load_err = load_assets(
    MODEL_DOWNLOAD_URL, MODEL_PATH, PREPROC_DOWNLOAD_URL, PREPROC_PATH
)
geo_reader = load_geo_reader(BUNDLED_GEO_PATH, GEO_DOWNLOAD_URL)

if load_err:
    st.error(f"Failed to load ML assets: {load_err}")
    st.stop()
if geo_reader is None:
    st.warning("GeoIP database not found or failed to load. Falling back to pseudo-geolocation.")

# --- Sidebar Controls ---
with st.sidebar:
    st.title("Ingest Controls")
    uploaded_files = st.file_uploader(
        "Upload dataset(s)", 
        accept_multiple_files=True, 
        type=["csv", "json", "parquet"]
    )
    st.markdown("---")
    st.markdown("OR fetch JSON via API")
    api_url = st.text_input("API URL")
    
    analysis_button = st.button("Fetch & Analyze")

# --- Analysis Logic ---
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None

if analysis_button:
    df_to_analyze = None
    if uploaded_files:
        all_dfs = [load_dataframe(f) for f in uploaded_files]
        df_to_analyze = pd.concat([df for df in all_dfs if df is not None])
        st.session_state.source_name = f"{len(uploaded_files)} files"
    elif api_url:
        try:
            r = requests.get(api_url, timeout=10)
            r.raise_for_status()
            data = r.json()
            df_to_analyze = pd.json_normalize(data)
            st.session_state.source_name = f"API: {api_url}"
        except Exception as e:
            st.error(f"API fetch error: {e}")
    
    if df_to_analyze is not None and not df_to_analyze.empty:
        with st.spinner("Running inference..."):
            results = run_inference(df_to_analyze, ml_model, scaler, feature_names, attack_map)
            st.session_state.analysis_results = results
            
            with st.spinner("Saving results to user_analysis.db..."):
                saved_count = save_analysis_to_db(results, st.session_state.source_name)
                if saved_count > 0:
                    st.success(f"Saved {saved_count} results to analysis_history.db.")
            
            st.success(f"Analysis complete for {st.session_state.source_name}")
    else:
        st.warning("No data to analyze.")

# --- Display Results ---
results_df = st.session_state.analysis_results

if results_df is None:
    st.info("Upload files or provide an API URL and click 'Fetch & Analyze' to begin.")
    st.stop()

st.header(f"Analysis Results for: {st.session_state.source_name}")

# --- KPIs ---
total_count = len(results_df)
threat_count = int((results_df["Predicted_Threat_Type"].astype(str) != "BENIGN").sum())
benign_count = total_count - threat_count
overall_risk = compute_overall_risk(results_df)

kpi_cols = st.columns(4)
kpi_cols[0].metric("Total Events", total_count)
kpi_cols[1].metric("Threats Found", threat_count)
kpi_cols[2].metric("Benign Events", benign_count)
kpi_cols[3].metric("Overall Risk Score", f"{overall_risk}%")

st.divider()

# --- Charts ---
chart_cols = st.columns(2)
with chart_cols[0]:
    st.subheader("Top Attack Categories")
    cat_counts = results_df["Predicted_Threat_Type"].astype(str).value_counts().reset_index()
    fig_cat = px.bar(cat_counts.head(20), x="count", y="Predicted_Threat_Type", orientation="h", title="Top Attack Categories")
    st.plotly_chart(fig_cat, use_container_width=True)

with chart_cols[1]:
    st.subheader("Event Types (Protocol)")
    proto_col = next((c for c in ["proto", "protocol", "service"] if c in results_df.columns), None)
    if proto_col:
        evt_counts = results_df[proto_col].astype(str).value_counts().reset_index()
        fig_evt = px.pie(evt_counts, names=proto_col, values="count", title="Event Protocols", hole=0.35)
        st.plotly_chart(fig_evt, use_container_width=True)
    else:
        st.info("No 'protocol' or 'service' column found for pie chart.")

st.divider()

# --- Map and Log Table ---
map_col, table_col = st.columns([1, 1])
with map_col:
    st.subheader("Geo-Threat Map (Source IP)")
    
    possible_ip_cols = ["srcip", "src_ip", "source ip", "source_ip", "Source IP", "Src IP", "sip"]
    ip_col = next((c for c in results_df.columns if c.lower() in possible_ip_cols), None)
    
    if ip_col and geo_reader:
        geo_df = results_df[[ip_col, "Predicted_Threat_Type"]].copy()
        geo_df = geo_df.dropna(subset=[ip_col])
        geo_df['geo_latlon'] = geo_df[ip_col].astype(str).apply(lambda ip: ip_to_geo(geo_reader, ip))
        geo_df['geo_lat'] = geo_df['geo_latlon'].apply(lambda t: t[0])
        geo_df['geo_lon'] = geo_df['geo_latlon'].apply(lambda t: t[1])
        
        agg = geo_df.groupby(["geo_lat", "geo_lon", "Predicted_Threat_Type"]).size().reset_index(name="count")
        agg["is_threat"] = agg["Predicted_Threat_Type"].astype(str) != "BENIGN"
        
        fig_map = px.scatter_geo(
            agg,
            lat="geo_lat",
            lon="geo_lon",
            scope="world",
            size="count",
            color="is_threat",
            hover_name="Predicted_Threat_Type",
            title="Source IP Locations"
        )
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No source IP column (e.g., 'src_ip') found or GeoIP reader not loaded.")

with table_col:
    st.subheader("Analyzed Log Table")
    show_only_threats = st.checkbox("Show only threats", value=False)
    display_df = results_df
    if show_only_threats:
        display_df = display_df[display_df["Predicted_Threat_Type"].astype(str) != "BENIGN"]
    st.dataframe(display_df.head(500), height=500)

st.divider()

# --- Reporting ---
st.header("Reporting & Export")
if st.button("Generate Threat Report (JSON)"):
    threats_only = results_df[results_df["Predicted_Threat_Type"].astype(str) != "BENIGN"]
    report = {
        "generated_at": datetime.now().isoformat(),
        "source": st.session_state.source_name,
        "total_events": len(results_df),
        "total_threats": len(threats_only),
        "threat_samples": threats_only.head(100).astype(str).to_dict("records")
    }
    st.download_button(
        "Download Threat Report (JSON)",
        data=json.dumps(report, indent=2),
        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d')}.json",
        mime="application/json"
    )

st.divider()
st.header("📖 Past Analysis History")
st.write("This table shows all results from past file/API analyses, saved in the cloud database.")

try:
    if analysis_engine:
        history_df = pd.read_sql("SELECT * FROM analysis_history ORDER BY _analyzed_at DESC LIMIT 1000", analysis_engine)
        st.dataframe(history_df, height=400)
    else:
        st.warning("Database connection for history not available.")
except Exception:
    st.info("No analysis history found yet.")