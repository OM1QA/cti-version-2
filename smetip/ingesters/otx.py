"""<auto> Ingesters split from the monolithic app.
These modules still use Streamlit for warnings and secrets, just like before.
"""
import re
import json
import time
import hashlib
from datetime import datetime, timedelta

import requests
import pandas as pd
import feedparser
from bs4 import BeautifulSoup
import streamlit as st

from ..scoring.confidence import calculate_confidence_score
from .base import BaseIngester


class OTXIngester(BaseIngester):
    """Ingest AlienVault OTX threat intelligence"""
    def __init__(self):
        super().__init__()
        self.source_name = "OTX"
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.api_key = st.secrets.get("OTX_API_KEY", "")
    
    def fetch_data(self):
        """Fetch OTX indicators"""
        if not self.api_key:
            st.warning("OTX API key not found. Using sample data.")
            return self.get_sample_iocs()
        
        try:
            headers = {
                'X-OTX-API-KEY': self.api_key,
                'User-Agent': 'SME-TIP/1.0'
            }
            
            # Fetch recent pulses (threat intelligence reports)
            pulses_url = f"{self.base_url}/pulses/subscribed"
            params = {
                'limit': 20,
                'page': 1
            }
            
            response = requests.get(pulses_url, headers=headers, params=params, timeout=15)
            response.raise_for_status()
            pulses_data = response.json()
            
            # Extract indicators from pulses
            indicators = []
            for pulse in pulses_data.get('results', [])[:10]:  # Limit for demo
                for indicator in pulse.get('indicators', [])[:5]:  # 5 per pulse
                    # Calculate confidence based on pulse quality and age
                    pulse_references = len(pulse.get('references', []))
                    created_date = self.parse_date(indicator.get('created', pulse.get('created', '')))
                    days_old = (datetime.now() - created_date).days if created_date else 0
                    
                    base_confidence = min(0.75 + (pulse_references * 0.02), 0.85)  # OTX varies in quality
                    confidence_score = calculate_confidence_score("OTX", base_confidence, days_old)
                    
                    indicators.append({
                        'indicator': indicator.get('indicator', 'N/A'),
                        'type': indicator.get('type', 'Unknown'),
                        'threat_type': self.classify_threat_type(pulse.get('name', '')),
                        'confidence': min(85 + len(pulse.get('references', [])) * 5, 100),
                        'first_seen': created_date,
                        'source': 'OTX',
                        'pulse_name': pulse.get('name', 'Unknown Pulse'),
                        'confidence_score': confidence_score
                    })
            
            return pd.DataFrame(indicators[:30])  # Limit total indicators
            
        except Exception as e:
            st.warning(f"Failed to fetch OTX data: {str(e)}. Using sample data.")
            return self.get_sample_iocs()
    
    def classify_threat_type(self, pulse_name):
        """Classify threat type based on pulse name"""
        pulse_lower = pulse_name.lower()
        if any(word in pulse_lower for word in ['ransomware', 'ransom']):
            return 'Ransomware'
        elif any(word in pulse_lower for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in pulse_lower for word in ['malware', 'trojan', 'backdoor']):
            return 'Malware C2'
        elif any(word in pulse_lower for word in ['botnet', 'bot']):
            return 'Botnet'
        elif any(word in pulse_lower for word in ['apt', 'advanced']):
            return 'APT Activity'
        else:
            return 'Suspicious Activity'
    
    def parse_date(self, date_string):
        """Parse various date formats"""
        try:
            if 'T' in date_string:
                return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            else:
                return datetime.strptime(date_string, '%Y-%m-%d')
        except:
            return datetime.now() - timedelta(days=1)
    
    def get_sample_iocs(self):
        """Fallback sample IOC data"""
        return pd.DataFrame({
            'indicator': ['192.168.1.100', 'malware.example.com', 'bad-hash-123'],
            'type': ['IPv4', 'hostname', 'FileHash-SHA256'],
            'threat_type': ['Malware C2', 'Phishing', 'Ransomware'],
            'confidence': [85, 92, 78],
            'first_seen': [datetime.now() - timedelta(days=2), datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=4)],
            'source': ['OTX', 'OTX', 'OTX'],
            'pulse_name': ['Sample Malware Campaign', 'Phishing Infrastructure', 'Ransomware IOCs']
        })
