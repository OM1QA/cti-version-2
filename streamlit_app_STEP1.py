import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
import requests
import json
import time
import feedparser
from bs4 import BeautifulSoup
import hashlib
import re
from collections import defaultdict

# Import project modules
from smetip.ransomware.store import clear_and_save, load_groups
from smetip.scoring.confidence import calculate_confidence_score
from smetip.utils.dedupe import deduplicate_vulnerabilities, deduplicate_indicators
from smetip.ingesters.base import BaseIngester
from smetip.ingesters.cisa_kev import CISAKEVIngester
from smetip.ingesters.otx import OTXIngester
from smetip.ingesters.abuse_ch import AbuseCHIngester
from smetip.ingesters.nvd import NVDIngester
from smetip.ingesters.cisa_advisories import CISAAdvisoriesIngester


# Page config
st.set_page_config(
    page_title="SME Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.critical-card { border-left-color: #dc3545; }
.high-card { border-left-color: #fd7e14; }
.medium-card { border-left-color: #ffc107; }
.low-card { border-left-color: #28a745; }
</style>
""", unsafe_allow_html=True)

# Utility Functions
def format_date(date_obj):
    if isinstance(date_obj, str):
        return date_obj
    return date_obj.strftime('%Y-%m-%d') if date_obj else 'Unknown'

def get_severity_color(severity):
    colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745'}
    return colors.get(severity, '#6c757d')

# Configuration constants
TOTAL_ITEMS_IN_FEED = 40
MIN_PER_SOURCE_IN_FEED = 2
MAX_PER_SOURCE_IN_FEED = 8
MAX_EXTRACT_SIZE = 150 * 1024

SOURCE_CONFIDENCE = {
    "CISA KEV": 0.95, "CISA Advisories": 0.95, "NVD": 0.90, "OTX": 0.75,
    "Abuse.ch ThreatFox": 0.85, "Abuse.ch URLhaus": 0.85, "CISA Alerts": 0.95,
    "UK NCSC News": 0.92, "ENISA News": 0.90, "The Hacker News": 0.70,
    "BleepingComputer": 0.75, "Cisco Talos": 0.85, "Microsoft Security Blog": 0.85,
    "Palo Alto Unit 42": 0.85
}

ACTORS = {"ALPHV", "BlackCat", "Scattered Spider", "Lapsus$", "FIN7", "Wizard Spider", "TA505", "APT29", "APT28"}
PRIORITY_TOPICS = {
    "ransomware": "topic:ransomware", "0-day": "topic:0day", "zero-day": "topic:0day",
    "phishing": "topic:phishing", "data breach": "topic:breach", "breach": "topic:breach",
    "credentials": "topic:credentials", "mfa": "topic:mfa", "supply chain": "topic:supply-chain",
}
VENDOR_KEYWORDS = ["microsoft", "office 365", "microsoft 365", "fortinet", "citrix", "atlassian", 
                   "progress", "vpn", "rdp", "exchange", "cisco", "vmware", "palo alto", "linux", 
                   "windows", "macos", "quickbooks", "invoice"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EXTRACT_WHITELIST = {"The Hacker News", "BleepingComputer", "Palo Alto Unit 42", 
                     "Microsoft Security Blog", "Cisco Talos", "CISA Alerts", "UK NCSC News", "ENISA News"}

def stable_id(title, link):
    return hashlib.sha256(f"{title}|{link}".encode()).hexdigest()[:16]

def parse_rss_date(date_string):
    try:
        parsed_date = feedparser._parse_date(date_string)
        if parsed_date:
            dt = datetime(*parsed_date[:6])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    except:
        pass
    return datetime.now(timezone.utc)

def extract_full_content(url, source_name):
    if source_name not in EXTRACT_WHITELIST:
        return ""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        if len(response.content) > MAX_EXTRACT_SIZE:
            return ""
        soup = BeautifulSoup(response.content, 'lxml')
        for script in soup(["script", "style", "nav", "footer", "header", "aside"]):
            script.decompose()
        content = soup.find('article') or soup.find('main') or soup.find('div', class_='content')
        if not content:
            content = soup.find('body')
        if content:
            text = content.get_text()
            return text[:MAX_EXTRACT_SIZE] if len(text) > MAX_EXTRACT_SIZE else text
        return ""
    except:
        return ""

def tag_item(text: str) -> list:
    tags = set()
    for match in CVE_RE.findall(text):
        tags.add(f"cve:{match.upper()}")
    text_lower = text.lower()
    for actor in ACTORS:
        if actor.lower() in text_lower:
            tags.add(f"actor:{actor}")
    for keyword, tag in PRIORITY_TOPICS.items():
        if keyword in text_lower:
            tags.add(tag)
    for vendor in VENDOR_KEYWORDS:
        if vendor in text_lower:
            tags.add(f"vendor:{vendor}")
    return sorted(tags)

def time_decay(published_dt: datetime) -> float:
    if not published_dt:
        return 0.8
    try:
        now = datetime.now(timezone.utc)
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        days = (now - published_dt).days
        if days <= 2: return 1.25
        elif days <= 7: return 1.0
        elif days <= 14: return 0.8
        else: return 0.6
    except:
        return 0.8

def compute_relevance(item: dict) -> int:
    tags = item.get("tags", [])
    cves = [t for t in tags if t.startswith("cve:")]
    actors = [t for t in tags if t.startswith("actor:")]
    topics = [t for t in tags if t.startswith("topic:")]
    vendors = [t for t in tags if t.startswith("vendor:")]
    score = 0
    score += min(len(set(cves)) * 4, 12)
    score += min(len(set(actors)) * 3, 9)
    priority_topics = {"topic:ransomware", "topic:0day", "topic:breach"}
    score += min(sum(1 for t in topics if t in priority_topics) * 2, 6)
    score += min(len(set(vendors)), 3)
    sme_vendors = ["vendor:microsoft", "vendor:microsoft 365", "vendor:office 365", 
                   "vendor:vpn", "vendor:rdp", "vendor:quickbooks"]
    sme_topics = ["topic:phishing", "topic:credentials"]
    if any(v in vendors for v in sme_vendors) or any(t in topics for t in sme_topics):
        score += 2
    score = int(round(score * time_decay(item.get("published_dt"))))
    return max(score, 0)

def mix_items_scored(items: list) -> list:
    by_src = defaultdict(list)
    for item in items:
        by_src[item["source"]].append(item)
    for source in by_src:
        by_src[source].sort(
            key=lambda x: (x["relevance_score"], x["published_dt"] or datetime.min.replace(tzinfo=timezone.utc)), 
            reverse=True
        )
    picked = []
    for _ in range(MIN_PER_SOURCE_IN_FEED):
        for source in list(by_src.keys()):
            if by_src[source] and sum(1 for x in picked if x["source"] == source) < MAX_PER_SOURCE_IN_FEED:
                picked.append(by_src[source].pop(0))
                if len(picked) >= TOTAL_ITEMS_IN_FEED:
                    return picked
    while len(picked) < TOTAL_ITEMS_IN_FEED:
        progressed = False
        for source in list(by_src.keys()):
            if by_src[source] and sum(1 for x in picked if x["source"] == source) < MAX_PER_SOURCE_IN_FEED:
                picked.append(by_src[source].pop(0))
                progressed = True
                if len(picked) >= TOTAL_ITEMS_IN_FEED:
                    break
        if not progressed:
            break
    return picked

@st.cache_data(ttl=7200, show_spinner=False)
def load_news():
    sources = [
        ("CISA Alerts", "https://www.cisa.gov/news-events/alerts/all.xml"),
        ("UK NCSC News", "https://www.ncsc.gov.uk/api/1/services/v1/news.rss"),
        ("ENISA News", "https://www.enisa.europa.eu/news/rss"),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
        ("Cisco Talos", "https://blog.talosintelligence.com/feed/"),
        ("Microsoft Security Blog", "https://www.microsoft.com/security/blog/feed/"),
        ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/")
    ]
    all_news = []
    for source_name, url in sources:
        try:
            feed = feedparser.parse(url)
            if hasattr(feed, 'entries') and feed.entries:
                for entry in feed.entries[:30]:
                    try:
                        title = entry.get('title', 'No title')
                        link = entry.get('link', '')
                        summary = entry.get('summary', entry.get('description', ''))
                        if summary:
                            soup = BeautifulSoup(summary, 'html.parser')
                            summary = soup.get_text().strip()
                        pub_date = entry.get('published', entry.get('pubDate', ''))
                        parsed_date = parse_rss_date(pub_date) if pub_date else datetime.now(timezone.utc)
                        full_text = f"{title} {summary}"
                        if source_name in EXTRACT_WHITELIST and link:
                            full_content = extract_full_content(link, source_name)
                            if full_content:
                                full_text += f" {full_content}"
                        tags = tag_item(full_text)
                        news_item = {
                            'id': stable_id(title, link), 'source': source_name, 'title': title,
                            'link': link, 'published_dt': parsed_date, 'summary_raw': summary,
                            'tags': tags, 'pub_date_str': pub_date
                        }
                        news_item['relevance_score'] = compute_relevance(news_item)
                        all_news.append(news_item)
                    except:
                        continue
        except:
            continue
    return mix_items_scored(all_news)

def get_ransomware_profile(group_name):
    profiles = {
        "LockBit": {
            "description": "LockBit is one of the most prolific ransomware-as-a-service (RaaS) operations, known for fast encryption and double extortion tactics.",
            "first_seen": "2019", "type": "Ransomware-as-a-Service (RaaS)",
            "tactics": ["Double extortion", "Fast encryption", "Affiliate recruitment"],
            "targets": ["Healthcare", "Manufacturing", "Government", "Education"],
            "notable_attacks": ["Accenture (2021)", "Continental AG (2022)", "Boeing supplier (2023)"],
            "status": "Active"
        },
        "ALPHV": {
            "description": "ALPHV (also known as BlackCat) is a sophisticated ransomware group using Rust programming language for cross-platform attacks.",
            "first_seen": "2021", "type": "Ransomware-as-a-Service (RaaS)",
            "tactics": ["Cross-platform attacks", "Triple extortion", "Advanced encryption"],
            "targets": ["Energy", "Healthcare", "Critical Infrastructure"],
            "notable_attacks": ["Reddit (2023)", "Western Digital (2023)", "MeridianLink (2023)"],
            "status": "Active"
        },
        "Cl0p": {
            "description": "Cl0p ransomware group specializes in targeting file transfer applications and mass exploitation campaigns.",
            "first_seen": "2019", "type": "Ransomware Group",
            "tactics": ["Supply chain attacks", "Mass exploitation", "Zero-day exploitation"],
            "targets": ["Financial services", "Manufacturing", "Retail"],
            "notable_attacks": ["MOVEit Transfer (2023)", "Accellion FTA (2021)", "GoAnywhere (2023)"],
            "status": "Active"
        }
    }
    return profiles.get(group_name, {
        "description": f"Information about {group_name} is being collected.",
        "first_seen": "Unknown", "type": "Ransomware Group",
        "tactics": ["Under investigation"], "targets": ["Various sectors"],
        "notable_attacks": ["Recent activities under analysis"], "status": "Under monitoring"
    })

def build_ransomware_groups(news_items=None, days_back=45):
    if news_items is None:
        news_items = load_news()
    ransomware_groups = {
        "LockBit": ["lockbit", "lockbit3"], "ALPHV": ["alphv", "blackcat"],
        "Cl0p": ["cl0p", "clop"], "BlackBasta": ["black basta", "blackbasta"],
        "Royal": ["royal ransomware", "royal"], "Play": ["play ransomware"],
        "BianLian": ["bianlian"], "Akira": ["akira ransomware", "akira"],
        "Rhysida": ["rhysida"], "Scattered Spider": ["scattered spider", "0ktapus"]
    }
    victim_patterns = [
        r'(?:attacked?|targeted?|hit|breached)\s+([A-Z][A-Za-z\s&.-]+(?:Inc|LLC|Corp|Ltd)?)',
        r'([A-Z][A-Za-z\s&.-]+(?:Inc|LLC|Corp)?)\s+(?:was|were)?\s*(?:attacked?|targeted?)'
    ]
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    recent_items = [i for i in news_items if i.get('published_dt', datetime.min.replace(tzinfo=timezone.utc)) >= cutoff_date]
    groups_data = {}
    for item in recent_items:
        content = f"{item.get('title', '')} {item.get('summary_raw', '')}".lower()
        if not any(kw in content for kw in ['ransomware', 'ransom', 'encrypted']):
            continue
        for group_name, aliases in ransomware_groups.items():
            if any(alias in content for alias in aliases):
                if group_name not in groups_data:
                    groups_data[group_name] = {
                        'aliases': aliases, 'last_seen': item.get('published_dt', datetime.now(timezone.utc)).strftime('%Y-%m-%d'),
                        'summary': f"Ransomware group tracked over {days_back} days",
                        'all_stories': [], 'attack_stories': [], 'victims': [], 'activity_score': 0
                    }
                story = {
                    'title': item.get('title', ''), 'link': item.get('link', ''),
                    'published': item.get('published_dt', datetime.now(timezone.utc)).strftime('%Y-%m-%d'),
                    'summary': item.get('summary_raw', '')[:200] + "..."
                }
                if story not in groups_data[group_name]['all_stories']:
                    groups_data[group_name]['all_stories'].append(story)
                    groups_data[group_name]['activity_score'] += 1
    for group_name in groups_data:
        groups_data[group_name]['all_stories'].sort(key=lambda x: x['published'], reverse=True)
        groups_data[group_name]['all_stories'] = groups_data[group_name]['all_stories'][:10]
    return {'groups': groups_data, 'last_updated': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

class RiskScorer:
    def __init__(self):
        self.threat_severity_map = {
            'Ransomware': 100, 'APT Activity': 95, 'Malware C2': 90,
            'Credential Theft': 85, 'Phishing': 80, 'Botnet': 75, 'Suspicious Activity': 60
        }
    
    def score_vulnerabilities(self, vuln_df):
        if vuln_df.empty:
            return vuln_df
        def calculate_vuln_risk(row):
            base_score = row.get('cvss_score', 5.0) * 10
            if row.get('source') == 'CISA KEV':
                base_score = max(base_score, 95)
            days_old = (datetime.now() - row.get('date_added', datetime.now())).days
            age_factor = max(1.0 - (days_old / 365), 0.5)
            return min(int(base_score * age_factor), 100)
        vuln_df = vuln_df.copy()
        vuln_df['risk_score'] = vuln_df.apply(calculate_vuln_risk, axis=1)
        return vuln_df
    
    def score_indicators(self, ioc_df):
        if ioc_df.empty:
            return ioc_df
        def calculate_ioc_risk(row):
            confidence = row.get('confidence', 50)
            threat_type = row.get('threat_type', 'Suspicious Activity')
            threat_severity = self.threat_severity_map.get(threat_type, 50)
            risk_score = (confidence * 0.6) + (threat_severity * 0.4)
            days_old = (datetime.now() - row.get('first_seen', datetime.now())).days
            if days_old <= 7:
                risk_score *= 1.1
            elif days_old <= 30:
                risk_score *= 1.05
            return min(int(risk_score), 100)
        ioc_df = ioc_df.copy()
        ioc_df['risk_score'] = ioc_df.apply(calculate_ioc_risk, axis=1)
        return ioc_df

@st.cache_data(ttl=3600, show_spinner=False)
def load_threat_data():
    try:
        cisa_ingester = CISAKEVIngester()
        otx_ingester = OTXIngester()
        abuse_ingester = AbuseCHIngester()
        scorer = RiskScorer()
        progress_bar = st.progress(0)
        status_text = st.empty()
        status_text.text("Loading CISA KEV...")
        progress_bar.progress(10)
        cisa_data = cisa_ingester.fetch_data()
        status_text.text("Loading OTX...")
        progress_bar.progress(40)
        otx_data = otx_ingester.fetch_data()
        status_text.text("Loading Abuse.ch...")
        progress_bar.progress(70)
        abuse_data = abuse_ingester.fetch_data()
        status_text.text("Processing...")
        progress_bar.progress(90)
        combined_iocs = pd.DataFrame()
        if not otx_data.empty and not abuse_data.empty:
            combined_iocs = pd.concat([otx_data, abuse_data], ignore_index=True)
        elif not otx_data.empty:
            combined_iocs = otx_data
        elif not abuse_data.empty:
            combined_iocs = abuse_data
        processed_data = {
            'vulnerabilities': scorer.score_vulnerabilities(cisa_data),
            'indicators': scorer.score_indicators(combined_iocs),
            'last_updated': datetime.now()
        }
        progress_bar.progress(100)
        status_text.text("✅ Loaded!")
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        return processed_data
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return {'vulnerabilities': pd.DataFrame(), 'indicators': pd.DataFrame(), 'last_updated': datetime.now()}

@st.cache_data(ttl=1800, show_spinner=False)
def load_threat_data_quick():
    try:
        progress_bar = st.progress(0)
        status_text = st.empty()
        status_text.text("Loading CISA KEV (Quick Mode)...")
        progress_bar.progress(50)
        cisa_ingester = CISAKEVIngester()
        cisa_data = cisa_ingester.fetch_data()
        scorer = RiskScorer()
        status_text.text("Processing...")
        progress_bar.progress(90)
        processed_data = {
            'vulnerabilities': scorer.score_vulnerabilities(cisa_data),
            'indicators': pd.DataFrame(),
            'last_updated': datetime.now()
        }
        progress_bar.progress(100)
        status_text.text("✅ Quick mode loaded!")
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        return processed_data
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return {'vulnerabilities': pd.DataFrame(), 'indicators': pd.DataFrame(), 'last_updated': datetime.now()}

def main():
    st.title("🛡️ SME Threat Intelligence Platform")
    st.markdown("**Enterprise-grade threat intelligence without enterprise costs**")
    
    with st.sidebar:
        st.header("⚙️ Settings")
        quick_mode = st.checkbox("Quick Mode", value=False, help="Skip OTX and Abuse.ch")
    
    data = load_threat_data_quick() if quick_mode else load_threat_data()
    
    if data['vulnerabilities'].empty and data['indicators'].empty:
        st.error("Unable to load data. Check API configuration.")
        st.stop()
    
    st.sidebar.header("🔍 Filters")
    severity_filter = st.sidebar.multiselect("Vulnerability Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    confidence_filter = st.sidebar.slider("IOC Confidence", 0, 100, 70)
    days_back = st.sidebar.selectbox("Show threats from last:", [7, 14, 30, 90], index=1)
    
    filtered_vulns = data['vulnerabilities'][
        (data['vulnerabilities']['severity'].isin(severity_filter)) &
        (data['vulnerabilities']['date_added'] >= datetime.now() - timedelta(days=days_back))
    ] if not data['vulnerabilities'].empty else pd.DataFrame()
    
    filtered_iocs = data['indicators'][
        (data['indicators']['confidence'] >= confidence_filter) &
        (data['indicators']['first_seen'] >= datetime.now() - timedelta(days=days_back))
    ] if not data['indicators'].empty else pd.DataFrame()
    
    st.header("📊 Executive Summary")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        critical_vulns = len(filtered_vulns[filtered_vulns['severity'] == 'Critical']) if not filtered_vulns.empty else 0
        st.markdown(f'<div class="metric-card critical-card"><h3 style="margin:0;color:#dc3545;">🚨 {critical_vulns}</h3><p style="margin:0;">Critical Vulnerabilities</p></div>', unsafe_allow_html=True)
    with col2:
        high_risk_iocs = len(filtered_iocs[filtered_iocs['risk_score'] >= 80]) if not filtered_iocs.empty else 0
        st.markdown(f'<div class="metric-card high-card"><h3 style="margin:0;color:#fd7e14;">⚠️ {high_risk_iocs}</h3><p style="margin:0;">High-Risk IOCs</p></div>', unsafe_allow_html=True)
    with col3:
        total_threats = len(filtered_vulns) + len(filtered_iocs)
        st.markdown(f'<div class="metric-card medium-card"><h3 style="margin:0;color:#ffc107;">📈 {total_threats}</h3><p style="margin:0;">Total Active Threats</p></div>', unsafe_allow_html=True)
    with col4:
        if critical_vulns > 5:
            posture, color = "🔴 HIGH", "#dc3545"
        elif critical_vulns > 2:
            posture, color = "🟡 MEDIUM", "#ffc107"
        else:
            posture, color = "🟢 LOW", "#28a745"
        st.markdown(f'<div class="metric-card"><h3 style="margin:0;color:{color};">{posture}</h3><p style="margin:0;">Risk Posture</p></div>', unsafe_allow_html=True)
    
    st.caption(f"Last updated: {data['last_updated'].strftime('%Y-%m-%d %H:%M:%S')}")
    
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["🎯 Priority", "🦠 Vulnerabilities", "🚩 Indicators", "📊 Analytics", "📰 News", "💥 Ransomware"])
    
    with tab1:
        st.subheader("🎯 Priority Actions")
        if not filtered_vulns.empty:
            st.markdown("### 🚨 Immediate Patching Required")
            for _, v in filtered_vulns.nlargest(5, 'risk_score').iterrows():
                with st.expander(f"🔥 {v['cve_id']} - {v['product']} (Risk: {v['risk_score']}/100)"):
                    st.write(f"**Description:** {v['description']}")
                    st.write(f"**Vendor:** {v['vendor']}")
                    st.write(f"**CVSS:** {v['cvss_score']}")
                    st.write(f"**Severity:** {v['severity']}")
                    st.write(f"**Date Added:** {format_date(v['date_added'])}")
        if not filtered_iocs.empty:
            st.markdown("### 🛡️ IOCs to Block")
            st.dataframe(filtered_iocs.nlargest(5, 'risk_score')[['indicator', 'type', 'threat_type', 'confidence', 'risk_score']], use_container_width=True)
    
    with tab2:
        st.subheader("🦠 Vulnerability Management")
        if not filtered_vulns.empty:
            fig = px.pie(filtered_vulns['severity'].value_counts(), title="By Severity", 
                        color_discrete_map={'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745'})
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(filtered_vulns[['cve_id', 'product', 'vendor', 'severity', 'cvss_score', 'risk_score', 'date_added']], use_container_width=True)
        else:
            st.info("No vulnerabilities match filters")
    
    with tab3:
        st.subheader("🚩 Threat Indicators")
        if not filtered_iocs.empty:
            fig = px.bar(filtered_iocs['type'].value_counts(), title="IOC Types")
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(filtered_iocs[['indicator', 'type', 'threat_type', 'confidence', 'source', 'first_seen']], use_container_width=True)
        else:
            st.info("No indicators match filters")
    
    with tab4:
        st.subheader("📊 Analytics")
        col1, col2 = st.columns(2)
        with col1:
            if not filtered_vulns.empty:
                fig = px.histogram(filtered_vulns, x='risk_score', nbins=20, title='Vuln Risk Distribution')
                st.plotly_chart(fig, use_container_width=True)
        with col2:
            if not filtered_iocs.empty:
                fig = px.bar(filtered_iocs.groupby('source')['confidence'].mean().reset_index(), 
                            x='source', y='confidence', title='Confidence by Source')
                st.plotly_chart(fig, use_container_width=True)
    
    with tab5:
        st.subheader("📰 Latest News")
        with st.sidebar:
            st.markdown("---")
            st.markdown("**📰 News Filters**")
            freshness_days = st.slider("Freshness (days)", 1, 30, 7)
            selected_topics = st.multiselect("Topics", ["CVE/Vulnerability", "Ransomware", "Phishing", "Data Breach"], default=[])
        
        try:
            with st.spinner("Loading news..."):
                news_items = load_news()
            if not news_items:
                st.warning("No news loaded")
            else:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=freshness_days)
                filtered_news = [i for i in news_items if i.get('published_dt', datetime.min.replace(tzinfo=timezone.utc)) >= cutoff_date]
                
                if selected_topics:
                    topic_map = {
                        "CVE/Vulnerability": ["cve:", "topic:0day"],
                        "Ransomware": ["topic:ransomware"],
                        "Phishing": ["topic:phishing"],
                        "Data Breach": ["topic:breach"]
                    }
                    topic_filtered = []
                    for item in filtered_news:
                        item_tags = item.get('tags', [])
                        for selected_topic in selected_topics:
                            target_tags = topic_map.get(selected_topic, [])
                            if any(any(tag.startswith(t) for t in target_tags) for tag in item_tags):
                                topic_filtered.append(item)
                                break
                    filtered_news = topic_filtered
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📰 Articles", len(filtered_news))
                with col2:
                    cve_count = len([i for i in filtered_news if any('cve:' in tag for tag in i.get('tags', []))])
                    st.metric("🔍 CVE Mentions", cve_count)
                with col3:
                    high_rel = len([i for i in filtered_news if i.get('relevance_score', 0) >= 5])
                    st.metric("⚠️ High Relevance", high_rel)
                
                st.markdown("---")
                
                if filtered_news:
                    for item in filtered_news[:20]:
                        st.markdown(f"**{item['title']}**")
                        if item.get('tags'):
                            display_tags = item['tags'][:6]
                            tag_display = " ".join([f"`{tag}`" for tag in display_tags])
                            st.markdown(tag_display)
                        if item.get('summary_raw'):
                            summary = item['summary_raw'][:300] + "..." if len(item['summary_raw']) > 300 else item['summary_raw']
                            st.write(summary)
                        if item.get('link'):
                            st.markdown(f"[🔗 Read article]({item['link']})")
                        if item.get('published_dt'):
                            st.caption(f"📅 {item['published_dt'].strftime('%Y-%m-%d %H:%M UTC')}")
                        st.markdown("---")
                else:
                    st.info("No items matched filters")
        except Exception as e:
            st.error(f"Error loading news: {str(e)}")
    
    with tab6:
        st.subheader("💥 Ransomware Groups Intelligence")
        with st.sidebar:
            st.markdown("---")
            st.markdown("**💥 Ransomware Analysis**")
            rw_days = st.slider("Analysis Window (days)", 7, 90, 45)
        
        try:
            with st.spinner("Analyzing ransomware activity..."):
                news_items = load_news()
                rw_payload = build_ransomware_groups(news_items, days_back=rw_days)
                saved_to_db = clear_and_save(rw_payload)
                groups = rw_payload.get("groups", {})
                last_updated = rw_payload.get("last_updated", "Unknown")
                
                all_group_names = set(groups.keys())
                profile_groups = ["LockBit", "ALPHV", "Cl0p", "BlackBasta", "Royal", "Play", 
                                "BianLian", "Akira", "Rhysida", "Scattered Spider"]
                all_group_names.update(profile_groups)
                all_groups_list = sorted(list(all_group_names))
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🎯 Tracked Groups", len(all_groups_list))
            with col2:
                st.metric("📊 Recently Active", len(groups))
            with col3:
                total_victims = sum(len(g.get('victims', [])) for g in groups.values())
                st.metric("🏢 Victims", total_victims)
            with col4:
                total_stories = sum(len(g.get('all_stories', [])) for g in groups.values())
                st.metric("📰 Coverage", total_stories)
            
            storage_status = "💾 SQLite" if saved_to_db else "🧠 In-Memory"
            st.caption(f"Updated: {last_updated} • Storage: {storage_status} • Period: {rw_days} days")
            st.markdown("---")
            
            st.markdown("### 🃏 Ransomware Groups Directory")
            st.caption("Click any group to view profile")
            
            if 'selected_ransomware_group' not in st.session_state:
                st.session_state.selected_ransomware_group = None
            
            num_cols = 4
            num_groups = len(all_groups_list)
            num_rows = (num_groups + num_cols - 1) // num_cols
            
            for row in range(num_rows):
                cols = st.columns(num_cols)
                for col_idx in range(num_cols):
                    group_idx = row * num_cols + col_idx
                    if group_idx < num_groups:
                        group_name = all_groups_list[group_idx]
                        group_data = groups.get(group_name, {})
                        with cols[col_idx]:
                            is_active = group_name in groups
                            activity_score = group_data.get('activity_score', 0)
                            victim_count = len(group_data.get('victims', []))
                            last_seen = group_data.get('last_seen', 'No recent activity')
                            button_style = "🔥" if is_active else "💤"
                            button_text = f"{button_style} {group_name}"
                            if st.button(button_text, key=f"group_{group_name}", help=f"View {group_name} profile", use_container_width=True):
                                st.session_state.selected_ransomware_group = group_name
                            if is_active:
                                st.caption(f"Activity: {activity_score} | Victims: {victim_count}")
                                st.caption(f"Last: {last_seen}")
                            else:
                                st.caption("No recent activity")
            
            st.markdown("---")
            
            if st.session_state.selected_ransomware_group:
                selected_group = st.session_state.selected_ransomware_group
                st.markdown(f"### 🔍 {selected_group} - Profile")
                profile = get_ransomware_profile(selected_group)
                group_data = groups.get(selected_group, {})
                
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**📋 Overview**")
                    st.write(f"**Description:** {profile['description']}")
                    st.write(f"**First Seen:** {profile['first_seen']}")
                    st.write(f"**Type:** {profile['type']}")
                    st.write(f"**Status:** {profile['status']}")
                    if profile.get('notable_attacks'):
                        st.markdown("**🎯 Notable Attacks:**")
                        for attack in profile['notable_attacks']:
                            st.write(f"• {attack}")
                
                with col2:
                    st.markdown("**⚔️ Tactics & Targeting**")
                    st.markdown("**Tactics:**")
                    for tactic in profile['tactics']:
                        st.write(f"• {tactic}")
                    st.markdown("**Targets:**")
                    for target in profile['targets']:
                        st.write(f"• {target}")
                    if group_data:
                        st.markdown("**📊 Recent Activity:**")
                        st.write(f"• **Last Activity:** {group_data.get('last_seen', 'Unknown')}")
                        st.write(f"• **Mentions:** {group_data.get('activity_score', 0)}")
                        st.write(f"• **Victims:** {len(group_data.get('victims', []))}")
                
                if group_data:
                    st.markdown("---")
                    st.markdown(f"**📰 Recent Intelligence on {selected_group}**")
                    if group_data.get('all_stories'):
                        tab_stories, tab_attacks = st.tabs(["All News", "Attack Reports"])
                        with tab_stories:
                            if group_data.get('all_stories'):
                                for story in group_data['all_stories'][:5]:
                                    st.write(f"**[{story['title']}]({story['link']})**")
                                    st.caption(f"Published: {story['published']}")
                                    if story.get('summary'):
                                        st.write(story['summary'])
                                    st.markdown("---")
                            else:
                                st.info("No recent news")
                        with tab_attacks:
                            if group_data.get('attack_stories'):
                                for story in group_data['attack_stories'][:3]:
                                    st.write(f"**[{story['title']}]({story['link']})**")
                                    st.caption(f"Published: {story['published']}")
                                    st.markdown("---")
                            else:
                                st.info("No attack reports")
                    else:
                        st.info(f"No recent intelligence for {selected_group}")
                
                if st.button("Clear Selection", key="clear_selection"):
                    st.session_state.selected_ransomware_group = None
                    st.rerun()
            else:
                st.info("👆 Select a group above to view profile")
            
            st.markdown("---")
            st.caption("🔥 = Recently active | 💤 = No recent activity")
            st.info("⚠️ **Disclaimer**: Automated analysis combined with curated profiles. Verify through official sources.")
        
        except Exception as e:
            st.error(f"Error analyzing ransomware: {str(e)}")
            st.info("Unable to analyze groups. May be due to dependencies or network issues.")
    
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ SME Threat Intelligence Platform MVP | Built with ❤️ for small businesses</p>
        <p>Data Sources: CISA KEV & Advisories, NVD, AlienVault OTX, Abuse.ch ThreatFox & URLhaus, 8 News Sources</p>
        <p>Features: Confidence scoring, deduplication, multi-source correlation | Auto-refresh: Every hour</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
