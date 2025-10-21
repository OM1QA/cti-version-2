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


class CISAAdvisoriesIngester(BaseIngester):
    """Ingest CISA Cybersecurity Advisories"""
    def __init__(self):
        super().__init__()
        self.source_name = "CISA Advisories"
        self.api_url = "https://www.cisa.gov/sites/default/files/feeds/cybersecurity_advisories.json"
    
    def fetch_data(self):
        """Fetch CISA advisories"""
        try:
            response = requests.get(self.api_url, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            advisories = []
            for advisory in data.get('advisories', [])[:30]:  # Limit for performance
                pub_date = advisory.get('published', '')
                if pub_date:
                    try:
                        pub_datetime = datetime.fromisoformat(pub_date)
                        days_old = (datetime.now() - pub_datetime).days
                    except:
                        days_old = 0
                else:
                    days_old = 0
                
                confidence_score = calculate_confidence_score("CISA Advisories", days_old=days_old)
                
                advisories.append({
                    'id': advisory.get('id', 'N/A'),
                    'title': advisory.get('title', 'No title'),
                    'description': advisory.get('description', 'No description available'),
                    'published': pub_datetime if pub_date and 'pub_datetime' in locals() else datetime.now(),
                    'source': 'CISA Advisories',
                    'confidence_score': confidence_score,
                    'link': advisory.get('link', '')
                })
            
            return pd.DataFrame(advisories)
            
        except Exception as e:
            st.warning(f"Failed to fetch CISA Advisories: {str(e)}. Using sample data.")
            return self.get_sample_advisories()
    
    def get_sample_advisories(self):
        """Fallback sample advisories data"""
        return pd.DataFrame({
            'id': ['CISA-2024-001', 'CISA-2024-002'],
            'title': ['Sample Advisory 1', 'Sample Advisory 2'],
            'description': ['Sample advisory description 1', 'Sample advisory description 2'],
            'published': [datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=2)],
            'source': ['CISA Advisories', 'CISA Advisories'],
            'confidence_score': [0.95, 0.95],
            'link': ['', '']
        })
