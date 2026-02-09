import pandas as pd
from sklearn.ensemble import IsolationForest

class LogAnalyzer:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)

    def load_logs(self, filepath):
        """
        Loads logs from a CSV file.
        Expects columns: source_ip, destination_port, protocol, bytes_transferred, timestamp
        """
        try:
            df = pd.read_csv(filepath)
            # Ensure proper data types
            df['bytes_transferred'] = pd.to_numeric(df['bytes_transferred'], errors='coerce')
            df['destination_port'] = pd.to_numeric(df['destination_port'], errors='coerce')
            df.dropna(inplace=True)
            return df
        except Exception as e:
            print(f"Error loading logs: {e}")
            return pd.DataFrame()

    def detect_anomalies(self, df):
        """
        Trains Isolation Forest and detects anomalies.
        Returns the DataFrame with an 'anomaly' column (-1 for anomaly, 1 for normal).
        """
        if df.empty:
            return df

        # Select features for anomaly detection
        # We focus on bytes_transferred and destination_port for this demo
        features = df[['bytes_transferred', 'destination_port']]

        # Train model
        self.model.fit(features)

        # Predict anomalies
        df['anomaly'] = self.model.predict(features)
        
        # Return only anomalies for further processing if needed, 
        # or return the whole DF with labels.
        # Here we return the whole DF so we can visualize it.
        return df
