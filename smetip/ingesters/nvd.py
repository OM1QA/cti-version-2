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


class NVDIngester(BaseIngester):
    """Ingest vulnerabilities from NVD (National Vulnerability Database)"""
    def __init__(self):
        super().__init__()
        self.source_name = "NVD"
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def fetch_data(self):
        """Fetch recent NVD vulnerabilities"""
        try:
            # Get vulnerabilities from last 7 days
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 50
            }
            
            response = requests.get(self.api_url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            vulns = []
            for cve_item in data.get('vulnerabilities', []):
                cve = cve_item.get('cve', {})
                cve_id = cve.get('id', 'N/A')
                
                # Get CVSS score
                cvss_score = 5.0  # Default
                severity = 'Medium'
                
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 5.0)
                    severity = cvss_data.get('baseSeverity', 'Medium').title()
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 5.0)
                    severity = cvss_data.get('baseSeverity', 'Medium').title()
                
                # Get description
                descriptions = cve.get('descriptions', [])
                description = 'No description available'
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', 'No description available')
                        break
                
                # Calculate confidence
                pub_date = cve.get('published', '')
                if pub_date:
                    try:
                        pub_datetime = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                        days_old = (datetime.now(timezone.utc) - pub_datetime).days
                    except:
                        days_old = 0
                else:
                    days_old = 0
                
                confidence_score = calculate_confidence_score("NVD", days_old=days_old)
                
                vulns.append({
                    'cve_id': cve_id,
                    'product': 'Various',  # NVD doesn't always specify
                    'vendor': 'Various',
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'date_added': datetime.now() - timedelta(days=days_old),
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'source': 'NVD',
                    'confidence_score': confidence_score
                })
            
            return pd.DataFrame(vulns)
            
        except Exception as e:
            st.warning(f"Failed to fetch NVD data: {str(e)}. Using sample data.")
            return self.get_sample_nvd_data()
    
    def get_sample_nvd_data(self):
        """Fallback sample NVD data"""
        return pd.DataFrame({
            'cve_id': ['CVE-2024-1001', 'CVE-2024-1002'],
            'product': ['Various', 'Various'],
            'vendor': ['Various', 'Various'],
            'severity': ['High', 'Medium'],
            'cvss_score': [8.5, 6.2],
            'date_added': [datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=2)],
            'description': ['Sample NVD vulnerability description', 'Another sample NVD entry'],
            'source': ['NVD', 'NVD'],
            'confidence_score': [0.90, 0.90]
        })
