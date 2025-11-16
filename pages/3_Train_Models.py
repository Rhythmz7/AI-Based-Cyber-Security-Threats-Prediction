# pages/3_Train_Models.py
import streamlit as st
import pandas as pd
import numpy as np
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from db_manager import Database

# --- Database Connection ---
@st.cache_resource
def get_db():
    # Reads credentials from Streamlit's secrets
    return Database(
        db_type="postgres",
        host=st.secrets["db_host"],
        port=st.secrets["db_port"],
        database=st.secrets["db_name"],
        user=st.secrets["db_user"],
        password=st.secrets["db_pass"]
    )

db = get_db()

@st.cache_data
def get_data_for_training():
    logs = db.query("SELECT * FROM logs LIMIT 5000")
    return pd.DataFrame(logs)

st.title("🤖 Train Custom AI/ML Models")
st.write("Train models on the live threat data collected in the database.")

df = get_data_for_training()

if len(df) < 50:
    st.warning(f"Not enough data. Need at least 50 records (found {len(df)}).")
else:
    st.write(f"Using {len(df)} records from the database.")
    
    # Feature engineering (from threat_dashboard.py)
    def preprocess(df):
        df_proc = df.copy()
        df_proc['country_encoded'] = df_proc['raw_json'].apply(lambda x: hash(json.loads(x).get('country', '')) % 100)
        df_proc['attack_encoded'] = df_proc['threat_type'].apply(lambda x: hash(x) % 100)
        df_proc['ip_sum'] = df_proc['src_ip'].apply(lambda ip: sum(int(p) for p in ip.split('.') if p.isdigit()))
        
        # Target: 1 if High/Critical (3 or 4), 0 otherwise
        df_proc['target'] = df_proc['severity'].apply(lambda x: 1 if int(x) >= 3 else 0)
        
        features = ['country_encoded', 'attack_encoded', 'ip_sum', 'severity']
        
        return df_proc[features], df_proc['target']

    X, y = preprocess(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model_options = st.multiselect(
        "Select models to train:",
        ['Random Forest', 'Logistic Regression', 'SVM'],
        default=['Random Forest', 'Logistic Regression']
    )

    if st.button("Train Selected Models"):
        results = {}
        for name in model_options:
            with st.spinner(f"Training {name}..."):
                if name == 'Random Forest':
                    model = RandomForestClassifier(random_state=42)
                elif name == 'Logistic Regression':
                    model = LogisticRegression(max_iter=1000, random_state=42)
                elif name == 'SVM':
                    model = SVC(kernel='rbf', random_state=42)
                
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                
                results[name] = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred, zero_division=0),
                    'recall': recall_score(y_test, y_pred, zero_division=0),
                    'f1': f1_score(y_test, y_pred, zero_division=0)
                }
        
        st.success("Training complete!")
        st.subheader("Model Performance Metrics")
        
        results_df = pd.DataFrame(results).T * 100
        st.dataframe(results_df.style.format("{:.2f}%"))