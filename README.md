---
title: AI NIDS Project
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: streamlit
sdk_version: 1.39.0
app_file: nids_main.py
pinned: false
---

# 🛡️ AI-Based Network Intrusion Detection System

This project implements an **AI-based Network Intrusion Detection System (NIDS)** using **Machine Learning (Random Forest)** to classify network traffic as **Benign or Malicious (DDoS)**.

The system supports both **real-world datasets (CIC-IDS2017)** and **randomly simulated network traffic**, making it suitable for testing, learning, and demonstration purposes.

---

## 🚀 Features
- Detects **DDoS attacks** using supervised machine learning
- Supports **CSV dataset upload** (CIC-IDS2017 format)
- Includes **simulated traffic generation** for quick testing
- Interactive **Streamlit dashboard** for training and analysis
- Live packet testing with real-time predictions

---

## 🧠 How It Works
1. Select a **data source** (Simulated Data or Upload CSV).
2. Train the **Random Forest model** using selected features.
3. View **accuracy, attack count, and confusion matrix**.
4. Test custom packet values using the **Live Packet Analysis** section.

---

## 📂 Project Files
- `nids_main.py` – Main Streamlit application
- `requirements.txt` – Required Python libraries
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` – CIC-IDS2017 dataset (optional)

---

## 🛠️ Technologies Used
- Python
- Streamlit
- Pandas & NumPy
- Scikit-learn
- Matplotlib & Seaborn

---

## 🎓 About the Project
This project was developed as part of a **university cybersecurity course** to demonstrate the practical application of **machine learning in network intrusion detection**.

---

## ▶️ Run the Application
```bash
pip install -r requirements.txt
streamlit run nids_main.py
