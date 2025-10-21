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


class AbuseCHIngester(BaseIngester):
    """Ingest Abuse.ch threat intelligence using authenticated APIs"""
    def __init__(self):
        super().__init__()
        self.source_name = "Abuse.ch"
        self.api_key = st.secrets.get("ABUSE_CH_API_KEY", "")
        self.apis = {
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1/',
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1/'
        }
    
    def fetch_data(self):
        """Fetch real Abuse.ch indicators using authenticated APIs"""
        if not self.api_key:
            st.warning("Abuse.ch API key not found. Using sample data.")
            return self.get_sample_data()
        
        try:
            all_indicators = []
            
            # Fetch from ThreatFox (IOCs) with timeout protection
            try:
                threatfox_data = self.fetch_threatfox()
                all_indicators.extend(threatfox_data)
            except Exception as e:
                st.warning(f"ThreatFox failed: {str(e)}")
            
            # Fetch from URLhaus (malicious URLs) with timeout protection
            try:
                urlhaus_data = self.fetch_urlhaus()
                all_indicators.extend(urlhaus_data)
            except Exception as e:
                st.warning(f"URLhaus failed: {str(e)}")
            
            # Return combined data
            if all_indicators:
                return pd.DataFrame(all_indicators[:30])
            else:
                return self.get_sample_data()
            
        except Exception as e:
            st.warning(f"Failed to fetch Abuse.ch data: {str(e)}. Using sample data.")
            return self.get_sample_data()
    
    def fetch_threatfox(self):
        """Fetch IOCs from ThreatFox using authenticated API"""
        try:
            payload = {
                'query': 'get_iocs',
                'days': 7
            }
            
            headers = {
                'Auth-Key': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'SME-TIP/1.0'
            }
            
            response = requests.post(
                self.apis['threatfox'], 
                json=payload,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()
            
            result = response.json()
            indicators = []
            
            if result.get('query_status') == 'ok':
                for ioc_entry in result.get('data', [])[:15]:
                    ioc_value = ioc_entry.get('ioc', '').strip()
                    if not ioc_value:
                        continue
                        
                    indicators.append({
                        'indicator': ioc_value,
                        'type': self.normalize_ioc_type(ioc_entry.get('ioc_type', '')),
                        'threat_type': self.classify_threatfox_threat(ioc_entry.get('malware', '')),
                        'confidence': self.calculate_threatfox_confidence(ioc_entry),
                        'first_seen': self.parse_abuse_date(ioc_entry.get('first_seen', '')),
                        'source': 'Abuse.ch ThreatFox',
                        'campaign': ioc_entry.get('malware', 'Unknown Malware'),
                        'confidence_level': ioc_entry.get('confidence_level', 50)
                    })
            
            return indicators
            
        except Exception as e:
            st.warning(f"ThreatFox API error: {str(e)}")
            return []
    
    def fetch_urlhaus(self):
        """Fetch malicious URLs from URLhaus using authenticated API"""
        try:
            payload = {
                'query': 'get_urls',
                'days': 3
            }
            
            headers = {
                'Auth-Key': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'SME-TIP/1.0'
            }
            
            response = requests.post(
                self.apis['urlhaus'],
                json=payload,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()
            
            result = response.json()
            indicators = []
            
            if result.get('query_status') == 'ok':
                for url_entry in result.get('urls', [])[:15]:
                    url = url_entry.get('url', '')
                    if not url:
                        continue
                    
                    # Extract domain from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        domain = parsed.netloc if parsed.netloc else url.split('/')[0]
                    except:
                        domain = url.split('/')[0] if '/' in url else url
                    
                    if not domain:
                        continue
                    
                    indicators.append({
                        'indicator': domain,
                        'type': 'hostname',
                        'threat_type': self.classify_urlhaus_threat(url_entry.get('tags', [])),
                        'confidence': self.calculate_urlhaus_confidence(url_entry),
                        'first_seen': self.parse_abuse_date(url_entry.get('date_added', '')),
                        'source': 'Abuse.ch URLhaus',
                        'campaign': url_entry.get('threat', 'Malicious URL'),
                        'url_status': url_entry.get('url_status', 'unknown'),
                        'full_url': url
                    })
            
            return indicators
            
        except Exception as e:
            st.warning(f"URLhaus API error: {str(e)}")
            return []
    
    def classify_threatfox_threat(self, malware_name):
        """Classify threat type based on malware family"""
        malware_lower = str(malware_name).lower()
        if any(word in malware_lower for word in ['emotet', 'trickbot', 'qakbot', 'banking']):
            return 'Banking Trojan'
        elif any(word in malware_lower for word in ['lockbit', 'conti', 'ryuk', 'ransom']):
            return 'Ransomware'
        elif any(word in malware_lower for word in ['cobalt', 'beacon']):
            return 'APT Activity'
        elif any(word in malware_lower for word in ['stealer', 'info']):
            return 'Credential Theft'
        else:
            return 'Malware C2'
    
    def classify_urlhaus_threat(self, tags):
        """Classify threat type based on URLhaus tags"""
        if not tags:
            return 'Malware C2'
        
        tags_str = ' '.join(tags).lower()
        if any(word in tags_str for word in ['emotet', 'trickbot', 'qakbot']):
            return 'Banking Trojan'
        elif any(word in tags_str for word in ['ransomware', 'lockbit', 'ryuk', 'sodinokibi']):
            return 'Ransomware'
        elif any(word in tags_str for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in tags_str for word in ['cobalt', 'beacon']):
            return 'APT Activity'
        elif any(word in tags_str for word in ['stealer', 'redline', 'vidar']):
            return 'Credential Theft'
        elif any(word in tags_str for word in ['malware', 'trojan']):
            return 'Malware C2'
        else:
            return 'Malicious Infrastructure'
    
    def calculate_threatfox_confidence(self, ioc_entry):
        """Calculate confidence score for ThreatFox entries"""
        base_confidence = 80
        confidence_rating = ioc_entry.get('confidence_level', 50)
        base_confidence = max(base_confidence, confidence_rating)
        return min(base_confidence, 98)
    
    def calculate_urlhaus_confidence(self, url_entry):
        """Calculate confidence score for URLhaus entries"""
        base_confidence = 80
        
        if url_entry.get('url_status') == 'online':
            base_confidence += 10
        
        tags_count = len(url_entry.get('tags', []))
        base_confidence += min(tags_count * 2, 10)
        
        threat = str(url_entry.get('threat', '')).lower()
        if any(family in threat for family in ['emotet', 'trickbot', 'cobalt', 'ransomware']):
            base_confidence += 5
        
        return min(base_confidence, 98)
    
    def normalize_ioc_type(self, ioc_type):
        """Normalize IOC types to standard format"""
        type_mapping = {
            'ip:port': 'IPv4',
            'domain': 'hostname',
            'url': 'URL',
            'md5_hash': 'FileHash-MD5',
            'sha1_hash': 'FileHash-SHA1',
            'sha256_hash': 'FileHash-SHA256',
            'email': 'email-addr'
        }
        return type_mapping.get(ioc_type.lower(), ioc_type)
    
    def parse_abuse_date(self, date_string):
        """Parse Abuse.ch date format"""
        try:
            if not date_string:
                return datetime.now() - timedelta(days=1)
            
            if 'T' in date_string:
                return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            else:
                return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        except:
            return datetime.now() - timedelta(days=1)
    
    def get_sample_data(self):
        """Fallback sample data"""
        return pd.DataFrame({
            'indicator': ['10.0.0.50', 'phishing.test.com', 'botnet.example.org'],
            'type': ['IPv4', 'hostname', 'hostname'],
            'threat_type': ['Botnet', 'Phishing', 'Botnet'],
            'confidence': [68, 95, 73],
            'first_seen': [datetime.now() - timedelta(days=6), datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=3)],
            'source': ['Abuse.ch', 'Abuse.ch', 'Abuse.ch'],
            'campaign': ['Emotet', 'Generic Phishing', 'Qakbot']
        })

# Risk Scoring Engine
