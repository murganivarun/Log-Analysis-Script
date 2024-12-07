import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

class LogAnalyzer:
    def __init__(self, csv_filepath):
        self.df = pd.read_csv(csv_filepath)
        self.columns_to_drop = ['IP Address', 'Request Count', 'Endpoint', 'Access Count', 'Failed Login Count']
        self.filter_df = self.df.drop(columns=self.columns_to_drop, errors='ignore')
        self.filter_df['time_received_datetimeobj'] = pd.to_datetime(self.filter_df['time_received_datetimeobj'])
        self.filter_df['date'] = self.filter_df['time_received_datetimeobj'].dt.date
        self.filter_df['time'] = self.filter_df['time_received_datetimeobj'].dt.time

    def count_requests_per_ip(self):
        requests_per_ip = self.filter_df['remote_host'].value_counts().sort_values(ascending=False)
        print("Count Requests per IP Address:")
        print(requests_per_ip)
        return requests_per_ip

    def most_frequently_accessed_endpoint(self):
        most_accessed_endpoints = self.filter_df['request_url_path'].value_counts().sort_values(ascending=False).head(10)
        print("Most Frequently Accessed Endpoint:")
        print(most_accessed_endpoints)
        return most_accessed_endpoints

    def detect_suspicious_activity(self, threshold=100):
        requests_per_ip = self.filter_df['remote_host'].value_counts()
        suspicious_ips = requests_per_ip[requests_per_ip > threshold]
        print("Suspicious Activity Detected (IPs with more than {} requests):".format(threshold))
        print(suspicious_ips)
        return suspicious_ips

    def analyze(self):
        self.count_requests_per_ip()
        self.most_frequently_accessed_endpoint()
        self.detect_suspicious_activity()
        return




