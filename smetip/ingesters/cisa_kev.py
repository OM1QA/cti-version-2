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


class CISAKEVIngester(BaseIngester):
    """Ingest CISA Known Exploited Vulnerabilities"""
    def __init__(self):
        super().__init__()
        self.source_name = "CISA KEV"
        self.api_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def fetch_data(self):
        """Fetch CISA KEV data"""
        try:
            response = requests.get(self.api_url, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            # Convert to DataFrame
            vulns = []
            for vuln in data.get('vulnerabilities', [])[:50]:  # Limit for demo
                days_old = (datetime.now() - datetime.strptime(vuln.get('dateAdded', '2024-01-01'), '%Y-%m-%d')).days
                confidence_score = calculate_confidence_score("CISA KEV", days_old=days_old)
                
                vulns.append({
                    'cve_id': vuln.get('cveID', 'N/A'),
                    'product': vuln.get('product', 'Unknown'),
                    'vendor': vuln.get('vendorProject', 'Unknown'),
                    'severity': 'Critical',  # CISA KEV are all critical
                    'cvss_score': 9.0,  # Default high score for KEV
                    'date_added': datetime.strptime(vuln.get('dateAdded', '2024-01-01'), '%Y-%m-%d'),
                    'description': vuln.get('shortDescription', 'No description available'),
                    'source': 'CISA KEV',
                    'confidence_score': confidence_score
                })
            
            return pd.DataFrame(vulns)
            
        except Exception as e:
            st.warning(f"Failed to fetch CISA KEV data: {str(e)}. Using sample data.")
            return self.get_sample_vulns()
    
    def get_sample_vulns(self):
        """Fallback sample vulnerability data"""
        return pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],
            'product': ['Microsoft Exchange', 'Apache Struts', 'WordPress Plugin'],
            'vendor': ['Microsoft', 'Apache', 'WordPress'],
            'severity': ['Critical', 'High', 'High'],
            'cvss_score': [9.8, 8.1, 7.5],
            'date_added': [datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=2), datetime.now() - timedelta(days=3)],
            'description': ['Remote code execution in Exchange Server', 'SQL injection in Struts framework', 'XSS vulnerability in popular plugin'],
            'source': ['CISA KEV', 'CISA KEV', 'CISA KEV'],
            'confidence_score': [0.95, 0.95, 0.95]
        })
