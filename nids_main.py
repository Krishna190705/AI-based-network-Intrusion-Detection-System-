import streamlit as st
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix

import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(page_title="AI NIDS ", layout="wide")

st.title("AI-Based Network Intrusion Detection System")
st.markdown(""" Detects **Benign vs Malicious (DDoS)** traffic using **Machine Learning**""")

@st.cache_data
def generate_simulated_data(samples=5000):
    np.random.seed(42)

    df = pd.DataFrame({
        "Destination_Port": np.random.randint(1, 65535, samples),
        "Flow_Duration": np.random.randint(10, 100000, samples),
        "Total_Fwd_Packets": np.random.randint(1, 100, samples),
        "Packet_Length_Mean": np.random.uniform(40, 1500, samples),
        "Active_Mean": np.random.uniform(0, 1000, samples),
        "Label": np.random.choice([0, 1], samples, p=[0.7, 0.3])
    })

    attack = df["Label"] == 1
    df.loc[attack, "Flow_Duration"] = np.random.randint(1, 2000, attack.sum())
    df.loc[attack, "Total_Fwd_Packets"] += np.random.randint(50, 200, attack.sum())

    return df

def load_dataset(file):
    df = pd.read_csv(file)

    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_")
        .str.replace("-", "_")
    )

    required = {
        "Destination_Port": ["Destination_Port", "Dst_Port"],
        "Flow_Duration": ["Flow_Duration"],
        "Total_Fwd_Packets": ["Total_Fwd_Packets"],
        "Packet_Length_Mean": ["Packet_Length_Mean"],
        "Active_Mean": ["Active_Mean"],
        "Label": ["Label"]
    }

    selected = {}

    for final, aliases in required.items():
        for col in aliases:
            if col in df.columns:
                selected[final] = col
                break

    if len(selected) != len(required):
        st.error("❌ Required columns missing in dataset")
        st.write("Detected columns:", df.columns.tolist())
        st.stop()

    df = df[list(selected.values())]
    df.columns = selected.keys()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    df["Label"] = df["Label"].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )

    return df

st.sidebar.header("Dataset")

data_mode = st.sidebar.radio(
    "Select Data Source",
    ["Simulated Data", "Upload CIC-IDS2017 CSV"]
)

df = None

if data_mode == "Simulated Data":
    samples = st.sidebar.slider("Number of Samples", 1000, 20000, 5000)
    df = generate_simulated_data(samples)
    st.sidebar.success(f"Simulated dataset loaded ({len(df)} rows)")

else:
    uploaded_file = st.sidebar.file_uploader(
        "Upload CIC-IDS2017 CSV File",
        type=["csv"]
    )

    if uploaded_file is not None:
        df = load_dataset(uploaded_file)
        st.sidebar.success(f"Dataset loaded ({len(df)} rows)")
    else:
        st.info("Please upload a CSV file")
        st.stop()

st.sidebar.header("Model Settings")

train_percent = st.sidebar.slider("Training Data (%)", 60, 90, 80)
trees = st.sidebar.slider("Number of Trees", 50, 300, 100)

X = df.drop("Label", axis=1)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=(100 - train_percent) / 100,
    random_state=42
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

st.subheader("Model Training")

if st.button("Train Model"):
    with st.spinner("Training model..."):
        model = RandomForestClassifier(
            n_estimators=trees,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train_scaled, y_train)

        st.session_state["model"] = model
        st.session_state["scaler"] = scaler
        st.success("Model trained successfully")

st.subheader("Detection Results")

if "model" in st.session_state:
    model = st.session_state["model"]
    y_pred = model.predict(X_test_scaled)

    acc = accuracy_score(y_test, y_pred)

    c1, c2, c3 = st.columns(3)
    c1.metric("Accuracy", f"{acc*100:.2f}%")
    c2.metric("Total Records", len(df))
    c3.metric("Attacks Detected", int(y_pred.sum()))

    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds", ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    st.pyplot(fig)
else:
    st.info("Train the model to view results")

st.subheader("Live Packet Analysis")

c1, c2, c3, c4, c5 = st.columns(5)

p1 = c1.number_input("Destination Port", 1, 65535, 80)
p2 = c2.number_input("Flow Duration", 1, 100000, 500)
p3 = c3.number_input("Total Fwd Packets", 1, 500, 50)
p4 = c4.number_input("Packet Length Mean", 10, 1500, 400)
p5 = c5.number_input("Active Mean", 0, 1000, 50)

if st.button("Analyze Packet"):
    if "model" not in st.session_state:
        st.error("Please train the model first")
    else:
        input_df = pd.DataFrame([[p1, p2, p3, p4, p5]], columns=X.columns)
        input_scaled = st.session_state["scaler"].transform(input_df)
        pred = st.session_state["model"].predict(input_scaled)[0]

        if pred == 1:
            st.error("🚨 MALICIOUS TRAFFIC DETECTED")
        else:
            st.success("✅ BENIGN TRAFFIC")
