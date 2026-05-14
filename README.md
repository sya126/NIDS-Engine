# 🛡️ Real-Time Network Intrusion Detection System (NIDS)

A full-stack, machine learning-powered Network Intrusion Detection System designed to analyze network traffic and classify potential cyber threats in real-time. 

## 👨‍💻 Author
* **Şeyma Adanalı, Ahmet Eren Yavuz, Sena Yolcuoğlu**

## 🧠 System Architecture & Tech Stack

This project is built using a modern decoupled architecture:

* **Frontend (Client):** React.js, Tailwind CSS (Provides a real-time threat analysis dashboard)
* **Backend (API):** Python, Flask (Handles packet sniffing and model serving)
* **Machine Learning:** XGBoost, Random Forest (Trained on the NSL-KDD dataset with SMOTE for class imbalance)

## 🎯 Threat Detection Capabilities

The AI engine is trained to classify network traffic into specific attack categories:
* **Normal:** Legitimate background traffic.
* **DoS (Denial of Service):** SYN Floods, Smurf attacks, Neptune.
* **Probe:** Port scanning and reconnaissance (e.g., Nmap scans).
* **R2L (Remote to Local):** Unauthorized access attempts from a remote machine.
* **U2R (User to Root):** Privilege escalation attacks.

## 🚀 How to Run the Project

### 1. Frontend Setup
Navigate to the `frontend` directory and start the React application:
```bash
cd frontend
npm install
npm start
```

2. Backend Setup
Navigate to the `backend` directory and start the Flask server:
```bash
cd backend
pip install -r requirements.txt
python nids_backend_api.py

(Note: Make sure to update the ngrok.set_auth_token() in nids_backend_api.py with your own token.)
```
## 📊 Dataset & Model Training
The model was trained using the benchmark NSL-KDD Dataset. Feature selection was applied using Tree-based Feature Importance to extract the top 20 most critical network parameters (e.g., count, serror_rate, dst_host_diff_srv_rate).

Note: Due to GitHub file size limits, the full dataset is not included. A sample test dataset (nids_perfect_demo.csv) is provided in the model_training directory for dashboard demonstration.
