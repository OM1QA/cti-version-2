import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import time
import feedparser
from bs4 import BeautifulSoup
import hashlib
import re
from ransomware_store import clear_and_save, load_groups

# Page config
st.set_page_config(
    page_title="SME Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.critical-card {
    border-left-color: #dc3545;
}
.high-card {
    border-left-color: #fd7e14;
}
.medium-card {
    border-left-color: #ffc107;
}
.low-card {
    border-left-color: #28a745;
}
</style>
""", unsafe_allow_html=True)

# Utility Functions
def format_date(date_obj):
    """Format date object to readable string"""
    if isinstance(date_obj, str):
        return date_obj
    return date_obj.strftime('%Y-%m-%d') if date_obj else 'Unknown'

def get_severity_color(severity):
    """Get color code for severity levels"""
    colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
    }
    return colors.get(severity, '#6c757d')

# News-related helper functions
import re
from collections import defaultdict
from datetime import timezone

# Configuration constants
TOTAL_ITEMS_IN_FEED = 40
MIN_PER_SOURCE_IN_FEED = 2
MAX_PER_SOURCE_IN_FEED = 8
MAX_EXTRACT_SIZE = 150 * 1024  # 150KB limit for extracted text

# Source confidence scoring (0.0 - 1.0)
SOURCE_CONFIDENCE = {
    "CISA KEV": 0.95,
    "CISA Advisories": 0.95,
    "NVD": 0.90,
    "OTX": 0.75,
    "Abuse.ch ThreatFox": 0.85,
    "Abuse.ch URLhaus": 0.85,
    "CISA Alerts": 0.95,
    "UK NCSC News": 0.92,
    "ENISA News": 0.90,
    "The Hacker News": 0.70,
    "BleepingComputer": 0.75,
    "Cisco Talos": 0.85,
    "Microsoft Security Blog": 0.85,
    "Palo Alto Unit 42": 0.85
}

def calculate_confidence_score(source, base_confidence=None, days_old=0, corroboration_count=0):
    """Calculate overall confidence score based on source, age, and corroboration"""
    if base_confidence is None:
        base_confidence = SOURCE_CONFIDENCE.get(source, 0.70)
    
    # Age factor: newer data gets higher confidence
    if days_old <= 1:
        age_factor = 1.0
    elif days_old <= 7:
        age_factor = 0.95
    elif days_old <= 30:
        age_factor = 0.90
    elif days_old <= 90:
        age_factor = 0.85
    else:
        age_factor = 0.80
    
    # Corroboration factor: multiple sources increase confidence
    corroboration_factor = min(1.0 + (corroboration_count * 0.05), 1.20)
    
    final_confidence = base_confidence * age_factor * corroboration_factor
    return min(final_confidence, 1.0)

def deduplicate_vulnerabilities(vuln_list):
    """Remove duplicate vulnerabilities based on CVE ID"""
    seen_cves = {}
    deduplicated = []
    
    for vuln in vuln_list:
        cve_id = vuln.get('cve_id', '').upper()
        if cve_id and cve_id != 'N/A':
            if cve_id in seen_cves:
                # Update existing entry with higher confidence source
                existing = seen_cves[cve_id]
                if vuln.get('confidence_score', 0) > existing.get('confidence_score', 0):
                    seen_cves[cve_id] = vuln
                    # Replace in deduplicated list
                    for i, item in enumerate(deduplicated):
                        if item.get('cve_id') == cve_id:
                            deduplicated[i] = vuln
                            break
            else:
                seen_cves[cve_id] = vuln
                deduplicated.append(vuln)
        else:
            # No CVE ID, add as-is
            deduplicated.append(vuln)
    
    return deduplicated

def deduplicate_indicators(ioc_list):
    """Remove duplicate IOCs based on indicator value"""
    seen_indicators = {}
    deduplicated = []
    
    for ioc in ioc_list:
        indicator = ioc.get('indicator', '').lower().strip()
        if indicator:
            if indicator in seen_indicators:
                # Keep the one with higher confidence
                existing = seen_indicators[indicator]
                if ioc.get('confidence_score', 0) > existing.get('confidence_score', 0):
                    seen_indicators[indicator] = ioc
                    # Replace in deduplicated list
                    for i, item in enumerate(deduplicated):
                        if item.get('indicator', '').lower().strip() == indicator:
                            deduplicated[i] = ioc
                            break
            else:
                seen_indicators[indicator] = ioc
                deduplicated.append(ioc)
        else:
            deduplicated.append(ioc)
    
    return deduplicated

# Enhanced tagging data
ACTORS = {"ALPHV", "BlackCat", "Scattered Spider", "Lapsus$", "FIN7", "Wizard Spider", "TA505", "APT29", "APT28"}
PRIORITY_TOPICS = {
    "ransomware": "topic:ransomware",
    "0-day": "topic:0day", "zero-day": "topic:0day",
    "phishing": "topic:phishing",
    "data breach": "topic:breach", "breach": "topic:breach",
    "credentials": "topic:credentials",
    "mfa": "topic:mfa",
    "supply chain": "topic:supply-chain",
}
VENDOR_KEYWORDS = ["microsoft", "office 365", "microsoft 365", "fortinet", "citrix", "atlassian", "progress",
                   "vpn", "rdp", "exchange", "cisco", "vmware", "palo alto", "linux", "windows", "macos", 
                   "quickbooks", "invoice"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Whitelisted sources for full content extraction
EXTRACT_WHITELIST = {
    "The Hacker News", "BleepingComputer", "Palo Alto Unit 42", 
    "Microsoft Security Blog", "Cisco Talos", "CISA Alerts", "UK NCSC News", "ENISA News"
}

def stable_id(title, link):
    """Generate stable ID for news items"""
    return hashlib.sha256(f"{title}|{link}".encode()).hexdigest()[:16]

def parse_rss_date(date_string):
    """Parse various RSS date formats with timezone awareness"""
    try:
        import feedparser
        parsed_date = feedparser._parse_date(date_string)
        if parsed_date:
            dt = datetime(*parsed_date[:6])
            # Make timezone-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    except:
        pass
    
    # Fallback to current time with UTC timezone
    return datetime.now(timezone.utc)

def extract_full_content(url, source_name):
    """Extract full article content for whitelisted sources"""
    if source_name not in EXTRACT_WHITELIST:
        return ""
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        if len(response.content) > MAX_EXTRACT_SIZE:
            return ""
        
        soup = BeautifulSoup(response.content, 'lxml')
        
        # Remove scripts and style elements
        for script in soup(["script", "style", "nav", "footer", "header", "aside"]):
            script.decompose()
        
        # Try to find main content
        content = soup.find('article') or soup.find('main') or soup.find('div', class_='content')
        if not content:
            content = soup.find('body')
        
        if content:
            text = content.get_text()
            return text[:MAX_EXTRACT_SIZE] if len(text) > MAX_EXTRACT_SIZE else text
        
        return ""
    except:
        return ""

def tag_item(text: str) -> list[str]:
    """Enhanced tagging with comprehensive detection"""
    tags = set()
    
    # CVE detection
    for match in CVE_RE.findall(text):
        tags.add(f"cve:{match.upper()}")
    
    text_lower = text.lower()
    
    # Threat actor detection
    for actor in ACTORS:
        if actor.lower() in text_lower:
            tags.add(f"actor:{actor}")
    
    # Priority topic detection
    for keyword, tag in PRIORITY_TOPICS.items():
        if keyword in text_lower:
            tags.add(tag)
    
    # Vendor keyword detection
    for vendor in VENDOR_KEYWORDS:
        if vendor in text_lower:
            tags.add(f"vendor:{vendor}")
    
    return sorted(tags)

def time_decay(published_dt: datetime) -> float:
    """Calculate time decay factor for relevance scoring"""
    if not published_dt:
        return 0.8
    
    try:
        # Ensure both timestamps are timezone-aware
        now = datetime.now(timezone.utc)
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        
        days = (now - published_dt).days
        
        if days <= 2:
            return 1.25
        elif days <= 7:
            return 1.0
        elif days <= 14:
            return 0.8
        else:
            return 0.6
    except:
        return 0.8

def compute_relevance(item: dict) -> int:
    """Compute relevance score based on tags and time"""
    tags = item.get("tags", [])
    
    cves = [t for t in tags if t.startswith("cve:")]
    actors = [t for t in tags if t.startswith("actor:")]
    topics = [t for t in tags if t.startswith("topic:")]
    vendors = [t for t in tags if t.startswith("vendor:")]
    
    score = 0
    
    # CVE points (max 12)
    score += min(len(set(cves)) * 4, 12)
    
    # Actor points (max 9)
    score += min(len(set(actors)) * 3, 9)
    
    # Priority topic points (max 6)
    priority_topics = {"topic:ransomware", "topic:0day", "topic:breach"}
    score += min(sum(1 for t in topics if t in priority_topics) * 2, 6)
    
    # Vendor points (max 3)
    score += min(len(set(vendors)), 3)
    
    # SME relevance bump
    sme_vendors = ["vendor:microsoft", "vendor:microsoft 365", "vendor:office 365", "vendor:vpn", 
                   "vendor:rdp", "vendor:quickbooks"]
    sme_topics = ["topic:phishing", "topic:credentials"]
    
    if any(v in vendors for v in sme_vendors) or any(t in topics for t in sme_topics):
        score += 2
    
    # Apply time decay
    score = int(round(score * time_decay(item.get("published_dt"))))
    
    return max(score, 0)

def mix_items_scored(items: list[dict]) -> list[dict]:
    """Mix items across sources for balanced representation"""
    by_src = defaultdict(list)
    
    # Group by source and sort by relevance/date
    for item in items:
        by_src[item["source"]].append(item)
    
    for source in by_src:
        by_src[source].sort(
            key=lambda x: (x["relevance_score"], x["published_dt"] or datetime.min.replace(tzinfo=timezone.utc)), 
            reverse=True
        )
    
    picked = []
    
    # First pass: ensure minimum per source
    for _ in range(MIN_PER_SOURCE_IN_FEED):
        for source in list(by_src.keys()):
            if by_src[source] and sum(1 for x in picked if x["source"] == source) < MAX_PER_SOURCE_IN_FEED:
                picked.append(by_src[source].pop(0))
                if len(picked) >= TOTAL_ITEMS_IN_FEED:
                    return picked
    
    # Second pass: fill remaining slots
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

@st.cache_data(ttl=7200, show_spinner=False)  # Cache for 2 hours
def load_news():
    """Load cybersecurity news from RSS feeds with enhanced processing"""
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
            # Parse RSS feed
            feed = feedparser.parse(url)
            
            # Check if feed parsed successfully
            if hasattr(feed, 'entries') and feed.entries:
                for entry in feed.entries[:30]:  # Increased from 10 to 30
                    try:
                        title = entry.get('title', 'No title')
                        link = entry.get('link', '')
                        summary = entry.get('summary', entry.get('description', ''))
                        
                        # Clean summary HTML
                        if summary:
                            soup = BeautifulSoup(summary, 'html.parser')
                            summary = soup.get_text().strip()
                        
                        # Parse publication date with timezone awareness
                        pub_date = entry.get('published', entry.get('pubDate', ''))
                        parsed_date = parse_rss_date(pub_date) if pub_date else datetime.now(timezone.utc)
                        
                        # Combine text for tagging
                        full_text = f"{title} {summary}"
                        
                        # Extract full content for whitelisted sources
                        if source_name in EXTRACT_WHITELIST and link:
                            full_content = extract_full_content(link, source_name)
                            if full_content:
                                full_text += f" {full_content}"
                        
                        # Extract tags
                        tags = tag_item(full_text)
                        
                        news_item = {
                            'id': stable_id(title, link),
                            'source': source_name,
                            'title': title,
                            'link': link,
                            'published_dt': parsed_date,
                            'summary_raw': summary,
                            'tags': tags,
                            'pub_date_str': pub_date
                        }
                        
                        # Compute relevance score
                        news_item['relevance_score'] = compute_relevance(news_item)
                        
                        all_news.append(news_item)
                        
                    except Exception as e:
                        continue  # Skip problematic entries
                        
        except Exception as e:
            # Silent failure as specified
            continue
    
    # Mix items for balanced representation
    mixed_news = mix_items_scored(all_news)
    
    return mixed_news

# Ransomware Groups Analysis
def get_ransomware_profile(group_name):
    """Get detailed profile information for ransomware groups"""
    profiles = {
        "LockBit": {
            "description": "LockBit is one of the most prolific ransomware-as-a-service (RaaS) operations, known for fast encryption and double extortion tactics.",
            "first_seen": "2019",
            "type": "Ransomware-as-a-Service (RaaS)",
            "tactics": ["Double extortion", "Fast encryption", "Affiliate recruitment"],
            "targets": ["Healthcare", "Manufacturing", "Government", "Education"],
            "notable_attacks": ["Accenture (2021)", "Continental AG (2022)", "Boeing supplier (2023)"],
            "status": "Active"
        },
        "ALPHV": {
            "description": "ALPHV (also known as BlackCat) is a sophisticated ransomware group using Rust programming language for cross-platform attacks.",
            "first_seen": "2021",
            "type": "Ransomware-as-a-Service (RaaS)",
            "tactics": ["Cross-platform attacks", "Triple extortion", "Advanced encryption"],
            "targets": ["Energy", "Healthcare", "Critical Infrastructure"],
            "notable_attacks": ["Reddit (2023)", "Western Digital (2023)", "MeridianLink (2023)"],
            "status": "Active"
        },
        "Cl0p": {
            "description": "Cl0p ransomware group specializes in targeting file transfer applications and mass exploitation campaigns.",
            "first_seen": "2019",
            "type": "Ransomware Group",
            "tactics": ["Supply chain attacks", "Mass exploitation", "Zero-day exploitation"],
            "targets": ["Financial services", "Manufacturing", "Retail"],
            "notable_attacks": ["MOVEit Transfer (2023)", "Accellion FTA (2021)", "GoAnywhere (2023)"],
            "status": "Active"
        },
        "BlackBasta": {
            "description": "BlackBasta is a relatively new but aggressive ransomware group known for targeting large organizations.",
            "first_seen": "2022",
            "type": "Ransomware Group",
            "tactics": ["Big game hunting", "Network infiltration", "Data theft"],
            "targets": ["Manufacturing", "Construction", "Technology"],
            "notable_attacks": ["Capita (2023)", "ABB (2022)", "Deutsche Windtechnik (2022)"],
            "status": "Active"
        },
        "Royal": {
            "description": "Royal ransomware emerged as a successor to Conti, focusing on high-value targets with sophisticated attack methods.",
            "first_seen": "2022",
            "type": "Ransomware Group",
            "tactics": ["Lateral movement", "Privilege escalation", "Custom tools"],
            "targets": ["Healthcare", "Education", "Communications"],
            "notable_attacks": ["Dallas city systems (2022)", "Royal Mail (2023)"],
            "status": "Active"
        },
        "Play": {
            "description": "Play ransomware group focuses on double extortion and has been increasingly active against various sectors.",
            "first_seen": "2022",
            "type": "Ransomware Group",
            "tactics": ["Double extortion", "Targeted attacks", "Social engineering"],
            "targets": ["Government", "Education", "Healthcare"],
            "notable_attacks": ["City of Oakland (2023)", "Prudential Financial (2023)"],
            "status": "Active"
        },
        "BianLian": {
            "description": "BianLian shifted from encryption-based ransomware to pure data theft and extortion tactics.",
            "first_seen": "2022",
            "type": "Data Extortion Group",
            "tactics": ["Data theft", "Extortion without encryption", "Fast deployment"],
            "targets": ["Healthcare", "Manufacturing", "Professional services"],
            "notable_attacks": ["Multiple healthcare providers (2023)", "Manufacturing companies (2023)"],
            "status": "Active"
        },
        "Akira": {
            "description": "Akira ransomware targets both Windows and Linux systems with a focus on enterprise environments.",
            "first_seen": "2023",
            "type": "Ransomware Group",
            "tactics": ["Cross-platform attacks", "Network scanning", "Credential theft"],
            "targets": ["Education", "Finance", "Real estate"],
            "notable_attacks": ["Yamaha Motor (2023)", "Multiple educational institutions"],
            "status": "Active"
        },
        "Rhysida": {
            "description": "Rhysida is an emerging ransomware group that has quickly gained attention for targeting critical infrastructure.",
            "first_seen": "2023",
            "type": "Ransomware Group",
            "tactics": ["Infrastructure targeting", "Healthcare focus", "Data publication"],
            "targets": ["Healthcare", "Education", "Government"],
            "notable_attacks": ["Prospect Medical Holdings (2023)", "Multiple hospitals"],
            "status": "Active"
        },
        "Scattered Spider": {
            "description": "Scattered Spider is known for sophisticated social engineering attacks and targeting cloud environments.",
            "first_seen": "2022",
            "type": "Cybercriminal Group",
            "tactics": ["Social engineering", "Cloud attacks", "SIM swapping"],
            "targets": ["Gaming", "Hospitality", "Technology"],
            "notable_attacks": ["MGM Resorts (2023)", "Caesars Entertainment (2023)"],
            "status": "Active"
        }
    }
    
    return profiles.get(group_name, {
        "description": f"Information about {group_name} is being collected. This group has been identified in recent threat intelligence reports.",
        "first_seen": "Unknown",
        "type": "Ransomware Group",
        "tactics": ["Under investigation"],
        "targets": ["Various sectors"],
        "notable_attacks": ["Recent activities under analysis"],
        "status": "Under monitoring"
    })

def build_ransomware_groups(news_items=None, days_back=45):
    """Analyze news items to extract ransomware group activity and all related news"""
    if news_items is None:
        news_items = load_news()
    
    # Known ransomware groups and their aliases
    ransomware_groups = {
        "LockBit": ["lockbit", "lockbit3", "lockbit 3.0", "lockbit 3"],
        "ALPHV": ["alphv", "blackcat", "black cat"],
        "Cl0p": ["cl0p", "clop"],
        "BlackBasta": ["black basta", "blackbasta"],
        "Royal": ["royal ransomware", "royal"],
        "Play": ["play ransomware", "play group"],
        "BianLian": ["bianlian", "bian lian"],
        "Akira": ["akira ransomware", "akira"],
        "Rhysida": ["rhysida"],
        "Scattered Spider": ["scattered spider", "0ktapus"],
        "Qilin": ["qilin", "agenda"],
        "RansomHub": ["ransomhub", "ransom hub"],
        "Cuba": ["cuba ransomware", "cuba"],
        "Medusa": ["medusa ransomware", "medusa"],
        "Conti": ["conti", "conti team"],
        "Hive": ["hive ransomware", "hive"],
        "Maze": ["maze ransomware", "maze"],
        "Sodinokibi": ["sodinokibi", "revil", "rEvil"],
        "Ryuk": ["ryuk", "ryuk ransomware"],
        "DarkSide": ["darkside", "dark side"]
    }
    
    # Victim extraction patterns
    victim_patterns = [
        r'(?:attacked?|targeted?|hit|breached|compromised|infected)\s+([A-Z][A-Za-z\s&.-]+(?:Inc|LLC|Corp|Ltd|Company|Group|Hospital|University|School|City|County|Government)?)',
        r'([A-Z][A-Za-z\s&.-]+(?:Inc|LLC|Corp|Ltd|Company|Group|Hospital|University|School|City|County|Government)?)\s+(?:was|were|has been|have been)?\s*(?:attacked?|targeted?|hit|breached|compromised|infected)',
        r'victims?\s+(?:include|includes?)?\s*([A-Z][A-Za-z\s&.-]+(?:Inc|LLC|Corp|Ltd|Company|Group|Hospital|University|School|City|County|Government)?)',
        r'ransomware\s+(?:attack|incident)\s+(?:on|at|against)\s+([A-Z][A-Za-z\s&.-]+(?:Inc|LLC|Corp|Ltd|Company|Group|Hospital|University|School|City|County|Government)?)'
    ]
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    recent_items = [
        item for item in news_items 
        if item.get('published_dt', datetime.min.replace(tzinfo=timezone.utc)) >= cutoff_date
    ]
    
    groups_data = {}
    
    for item in recent_items:
        title = item.get('title', '')
        summary = item.get('summary_raw', '')
        content = f"{title} {summary}".lower()
        
        # Check if this is ransomware-related (broader check)
        ransomware_keywords = ['ransomware', 'ransom', 'encrypted', 'lockbit', 'alphv', 'blackcat', 
                              'crypto-locker', 'file encryption', 'ransom payment', 'ransom demand',
                              'ransomware-as-a-service', 'raas', 'double extortion']
        
        if not any(keyword in content for keyword in ransomware_keywords):
            continue
        
        # Find matching ransomware groups
        for group_name, aliases in ransomware_groups.items():
            if any(alias in content for alias in aliases):
                if group_name not in groups_data:
                    groups_data[group_name] = {
                        'aliases': aliases,
                        'last_seen': item.get('published_dt', datetime.now(timezone.utc)).strftime('%Y-%m-%d'),
                        'summary': f"Ransomware group tracked over {days_back} days",
                        'all_stories': [],  # All news mentioning the group
                        'attack_stories': [],  # Stories specifically about attacks/victims
                        'victims': [],
                        'activity_score': 0
                    }
                
                # Categorize the story
                story = {
                    'title': title,
                    'link': item.get('link', ''),
                    'published': item.get('published_dt', datetime.now(timezone.utc)).strftime('%Y-%m-%d'),
                    'summary': summary[:200] + "..." if len(summary) > 200 else summary
                }
                
                # Add to all stories
                if story not in groups_data[group_name]['all_stories']:
                    groups_data[group_name]['all_stories'].append(story)
                    groups_data[group_name]['activity_score'] += 1
                
                # Check if it's an attack story (mentions victims/attacks)
                attack_keywords = ['attack', 'victim', 'breach', 'compromise', 'encrypt', 'ransom demand']
                if any(keyword in content for keyword in attack_keywords):
                    if story not in groups_data[group_name]['attack_stories']:
                        groups_data[group_name]['attack_stories'].append(story)
                        groups_data[group_name]['activity_score'] += 2  # Higher weight for attack stories
                
                # Update last seen date
                current_date = item.get('published_dt', datetime.now(timezone.utc)).strftime('%Y-%m-%d')
                if current_date > groups_data[group_name]['last_seen']:
                    groups_data[group_name]['last_seen'] = current_date
                
                # Extract potential victims from attack stories
                if any(keyword in content for keyword in attack_keywords):
                    full_text = f"{title} {summary}"
                    for pattern in victim_patterns:
                        matches = re.findall(pattern, full_text, re.IGNORECASE)
                        for match in matches:
                            victim_name = match.strip()
                            # Filter out common false positives
                            if (len(victim_name) > 3 and 
                                victim_name.lower() not in ['the company', 'the organization', 'the victim', 'their data'] and
                                not victim_name.lower().startswith(('this', 'that', 'these', 'those', 'some', 'many'))):
                                
                                victim = {
                                    'name': victim_name,
                                    'date': current_date,
                                    'source': item.get('link', '')
                                }
                                
                                # Avoid duplicates
                                if victim not in groups_data[group_name]['victims']:
                                    groups_data[group_name]['victims'].append(victim)
    
    # Limit stories and victims per group, sort by date
    for group_name in groups_data:
        # Sort all stories by date (newest first)
        groups_data[group_name]['all_stories'].sort(key=lambda x: x['published'], reverse=True)
        groups_data[group_name]['attack_stories'].sort(key=lambda x: x['published'], reverse=True)
        
        # Limit to most recent
        groups_data[group_name]['all_stories'] = groups_data[group_name]['all_stories'][:10]
        groups_data[group_name]['attack_stories'] = groups_data[group_name]['attack_stories'][:5]
        groups_data[group_name]['victims'] = groups_data[group_name]['victims'][:20]
    
    return {
        'groups': groups_data,
        'last_updated': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    }

# Data Ingestion Classes
class BaseIngester:
    """Base class for threat intelligence ingesters"""
    def __init__(self):
        self.source_name = "Base"
        
    def fetch_data(self):
        """Override this method in child classes"""
        return []

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
                    'published': pub_datetime if pub_date else datetime.now(),
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
class RiskScorer:
    """Calculate risk scores for threats"""
    def __init__(self):
        self.threat_severity_map = {
            'Ransomware': 100,
            'APT Activity': 95,
            'Malware C2': 90,
            'Credential Theft': 85,
            'Phishing': 80,
            'Botnet': 75,
            'Suspicious Activity': 60
        }
    
    def score_vulnerabilities(self, vuln_df):
        """Score vulnerabilities based on CVSS and other factors"""
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
        """Score IOCs based on confidence and threat type"""
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
    """Load and process threat intelligence data"""
    try:
        cisa_ingester = CISAKEVIngester()
        otx_ingester = OTXIngester()
        abuse_ingester = AbuseCHIngester()
        
        scorer = RiskScorer()
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Loading CISA KEV vulnerabilities...")
        progress_bar.progress(10)
        cisa_data = cisa_ingester.fetch_data()
        
        status_text.text("Loading OTX threat intelligence...")
        progress_bar.progress(40)
        otx_data = otx_ingester.fetch_data()
        
        status_text.text("Loading Abuse.ch indicators...")
        progress_bar.progress(70)
        abuse_data = abuse_ingester.fetch_data()
        
        status_text.text("Processing and scoring threats...")
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
        status_text.text("✅ Threat data loaded successfully!")
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        return processed_data
    
    except Exception as e:
        st.error(f"Error loading threat data: {str(e)}")
        return {
            'vulnerabilities': pd.DataFrame(),
            'indicators': pd.DataFrame(),
            'last_updated': datetime.now()
        }

@st.cache_data(ttl=1800, show_spinner=False)
def load_threat_data_quick():
    """Load only CISA KEV data for quick startup"""
    try:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Loading CISA KEV vulnerabilities (Quick Mode)...")
        progress_bar.progress(50)
        
        cisa_ingester = CISAKEVIngester()
        cisa_data = cisa_ingester.fetch_data()
        
        scorer = RiskScorer()
        
        status_text.text("Processing vulnerabilities...")
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
        st.error(f"Error in quick mode: {str(e)}")
        return {
            'vulnerabilities': pd.DataFrame(),
            'indicators': pd.DataFrame(),
            'last_updated': datetime.now()
        }

def main():
    st.title("🛡️ SME Threat Intelligence Platform")
    st.markdown("**Enterprise-grade threat intelligence without enterprise costs**")
    
    # Add a quick mode toggle
    with st.sidebar:
        st.header("⚙️ Settings")
        quick_mode = st.checkbox("Quick Mode (Skip slow APIs)", value=False, help="Skip OTX and Abuse.ch if they're slow")
    
    # Load data with optional quick mode
    if quick_mode:
        data = load_threat_data_quick()
    else:
        data = load_threat_data()
    
    # Check if we have data
    if data['vulnerabilities'].empty and data['indicators'].empty:
        st.error("Unable to load threat intelligence data. Please check your API configuration.")
        st.stop()
    
    # Sidebar filters
    st.sidebar.header("🔍 Filters")
    
    # Severity filter for vulnerabilities
    severity_filter = st.sidebar.multiselect(
        "Vulnerability Severity",
        ['Critical', 'High', 'Medium', 'Low'],
        default=['Critical', 'High']
    )
    
    # Confidence filter for IOCs
    confidence_filter = st.sidebar.slider(
        "IOC Confidence Threshold",
        min_value=0,
        max_value=100,
        value=70,
        help="Only show indicators with confidence above this threshold"
    )
    
    # Date filter
    days_back = st.sidebar.selectbox(
        "Show threats from last:",
        [7, 14, 30, 90],
        index=1
    )
    
    # Filter data based on selections
    filtered_vulns = data['vulnerabilities'][
        (data['vulnerabilities']['severity'].isin(severity_filter)) &
        (data['vulnerabilities']['date_added'] >= datetime.now() - timedelta(days=days_back))
    ] if not data['vulnerabilities'].empty else pd.DataFrame()
    
    filtered_iocs = data['indicators'][
        (data['indicators']['confidence'] >= confidence_filter) &
        (data['indicators']['first_seen'] >= datetime.now() - timedelta(days=days_back))
    ] if not data['indicators'].empty else pd.DataFrame()
    
    # Executive Summary Section
    st.header("📊 Executive Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        critical_vulns = len(filtered_vulns[filtered_vulns['severity'] == 'Critical']) if not filtered_vulns.empty else 0
        st.markdown(f"""
        <div class="metric-card critical-card">
            <h3 style="margin:0; color:#dc3545;">🚨 {critical_vulns}</h3>
            <p style="margin:0;">Critical Vulnerabilities</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        high_risk_iocs = len(filtered_iocs[filtered_iocs['risk_score'] >= 80]) if not filtered_iocs.empty else 0
        st.markdown(f"""
        <div class="metric-card high-card">
            <h3 style="margin:0; color:#fd7e14;">⚠️ {high_risk_iocs}</h3>
            <p style="margin:0;">High-Risk IOCs</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        total_threats = len(filtered_vulns) + len(filtered_iocs)
        st.markdown(f"""
        <div class="metric-card medium-card">
            <h3 style="margin:0; color:#ffc107;">📈 {total_threats}</h3>
            <p style="margin:0;">Total Active Threats</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        # Calculate risk posture (simplified)
        if critical_vulns > 5:
            posture = "🔴 HIGH"
            posture_color = "#dc3545"
        elif critical_vulns > 2:
            posture = "🟡 MEDIUM" 
            posture_color = "#ffc107"
        else:
            posture = "🟢 LOW"
            posture_color = "#28a745"
            
        st.markdown(f"""
        <div class="metric-card">
            <h3 style="margin:0; color:{posture_color};">{posture}</h3>
            <p style="margin:0;">Risk Posture</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Last updated info
    st.caption(f"Last updated: {data['last_updated'].strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Data source status
    with st.expander("🔗 Data Source Status"):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("CISA KEV", f"{len(data['vulnerabilities'])} vulnerabilities")
        with col2:
            otx_count = len(data['indicators'][data['indicators']['source'] == 'OTX']) if not data['indicators'].empty else 0
            st.metric("AlienVault OTX", f"{otx_count} indicators")
        with col3:
            threatfox_count = len(data['indicators'][data['indicators']['source'] == 'Abuse.ch ThreatFox']) if not data['indicators'].empty else 0
            st.metric("ThreatFox", f"{threatfox_count} IOCs")
        with col4:
            urlhaus_count = len(data['indicators'][data['indicators']['source'] == 'Abuse.ch URLhaus']) if not data['indicators'].empty else 0
            st.metric("URLhaus", f"{urlhaus_count} URLs")
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["🎯 Priority Actions", "🦠 Vulnerabilities", "🚩 Indicators", "📊 Analytics", "📰 News", "💥 Ransomware"])
    
    with tab1:
        st.subheader("🎯 Priority Actions for Your Team")
        
        # Top critical vulnerabilities
        if not filtered_vulns.empty:
            st.markdown("### 🚨 Immediate Patching Required")
            top_vulns = filtered_vulns.nlargest(5, 'risk_score')
            
            for _, vuln in top_vulns.iterrows():
                with st.expander(f"🔥 {vuln['cve_id']} - {vuln['product']} (Risk: {vuln['risk_score']}/100)"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Description:** {vuln['description']}")
                        st.write(f"**Vendor:** {vuln['vendor']}")
                        st.write(f"**CVSS Score:** {vuln['cvss_score']}")
                    with col2:
                        st.write(f"**Severity:** {vuln['severity']}")
                        st.write(f"**Date Added:** {format_date(vuln['date_added'])}")
                        if st.button(f"Track Patching", key=f"patch_{vuln['cve_id']}"):
                            st.success("Added to patch management queue (Demo)")
        
        # Top IOCs to block
        if not filtered_iocs.empty:
            st.markdown("### 🛡️ IOCs to Block Immediately")
            top_iocs = filtered_iocs.nlargest(5, 'risk_score')
            
            ioc_df = top_iocs[['indicator', 'type', 'threat_type', 'confidence', 'risk_score']]
            st.dataframe(ioc_df, use_container_width=True)
            
            if st.button("🚫 Block Selected IOCs"):
                st.success(f"Would block {len(top_iocs)} high-risk indicators across your security stack (Demo)")
    
    with tab2:
        st.subheader("🦠 Vulnerability Management")
        
        if not filtered_vulns.empty:
            # Add confidence filter in columns
            col1, col2 = st.columns(2)
            with col1:
                confidence_threshold = st.slider(
                    "Minimum Confidence Score",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.7,
                    step=0.05,
                    help="Filter vulnerabilities by confidence score"
                )
            
            with col2:
                sort_by = st.selectbox(
                    "Sort by",
                    ["Risk Score", "Confidence Score", "CVSS Score", "Date Added"],
                    help="Choose how to sort vulnerabilities"
                )
            
            # Apply confidence filter
            if 'confidence_score' in filtered_vulns.columns:
                conf_filtered_vulns = filtered_vulns[filtered_vulns['confidence_score'] >= confidence_threshold]
            else:
                conf_filtered_vulns = filtered_vulns
            
            # Apply sorting
            if not conf_filtered_vulns.empty:
                if sort_by == "Risk Score":
                    conf_filtered_vulns = conf_filtered_vulns.sort_values('risk_score', ascending=False)
                elif sort_by == "Confidence Score" and 'confidence_score' in conf_filtered_vulns.columns:
                    conf_filtered_vulns = conf_filtered_vulns.sort_values('confidence_score', ascending=False)
                elif sort_by == "CVSS Score":
                    conf_filtered_vulns = conf_filtered_vulns.sort_values('cvss_score', ascending=False)
                elif sort_by == "Date Added":
                    conf_filtered_vulns = conf_filtered_vulns.sort_values('date_added', ascending=False)
            
            # Vulnerability distribution chart
            severity_counts = conf_filtered_vulns['severity'].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Distribution by Severity",
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14', 
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
            )
            st.plotly_chart(fig_severity, use_container_width=True)
            
            # Source distribution if we have multiple sources
            if 'source' in conf_filtered_vulns.columns:
                col1, col2 = st.columns(2)
                with col1:
                    source_counts = conf_filtered_vulns['source'].value_counts()
                    fig_sources = px.bar(
                        x=source_counts.index,
                        y=source_counts.values,
                        title="Vulnerabilities by Source",
                        labels={'x': 'Source', 'y': 'Count'}
                    )
                    st.plotly_chart(fig_sources, use_container_width=True)
                
                with col2:
                    # Confidence distribution
                    if 'confidence_score' in conf_filtered_vulns.columns:
                        fig_conf = px.histogram(
                            conf_filtered_vulns,
                            x='confidence_score',
                            nbins=20,
                            title='Confidence Score Distribution'
                        )
                        st.plotly_chart(fig_conf, use_container_width=True)
            else:
                # Risk score distribution
                fig_risk = px.histogram(
                    conf_filtered_vulns,
                    x='risk_score',
                    nbins=20,
                    title='Vulnerability Risk Score Distribution'
                )
                st.plotly_chart(fig_risk, use_container_width=True)
            
            # Detailed vulnerability table
            st.markdown("### 📋 Detailed Vulnerability List")
            
            # Prepare display columns
            display_columns = ['cve_id', 'product', 'vendor', 'severity', 'cvss_score', 'risk_score', 'source', 'date_added']
            if 'confidence_score' in conf_filtered_vulns.columns:
                display_columns.insert(-1, 'confidence_score')
            
            # Format confidence score for display
            vuln_display = conf_filtered_vulns[display_columns].copy()
            if 'confidence_score' in vuln_display.columns:
                vuln_display['confidence_score'] = vuln_display['confidence_score'].round(2)
            
            st.dataframe(vuln_display, use_container_width=True)
            
            # Show statistics
            st.caption(f"Showing {len(conf_filtered_vulns)} vulnerabilities (filtered from {len(filtered_vulns)} total)")
            
        else:
            st.info("No vulnerabilities match your current filters.")
    
    with tab3:
        st.subheader("🚩 Threat Indicators")
        
        if not filtered_iocs.empty:
            # Add confidence filter and sorting
            col1, col2 = st.columns(2)
            with col1:
                ioc_confidence_threshold = st.slider(
                    "Minimum IOC Confidence Score",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.6,
                    step=0.05,
                    help="Filter indicators by confidence score"
                )
            
            with col2:
                ioc_sort_by = st.selectbox(
                    "Sort IOCs by",
                    ["Risk Score", "Confidence Score", "Confidence", "First Seen"],
                    help="Choose how to sort indicators"
                )
            
            # Apply confidence filter
            if 'confidence_score' in filtered_iocs.columns:
                conf_filtered_iocs = filtered_iocs[filtered_iocs['confidence_score'] >= ioc_confidence_threshold]
            else:
                conf_filtered_iocs = filtered_iocs
            
            # Apply sorting
            if not conf_filtered_iocs.empty:
                if ioc_sort_by == "Risk Score":
                    conf_filtered_iocs = conf_filtered_iocs.sort_values('risk_score', ascending=False)
                elif ioc_sort_by == "Confidence Score" and 'confidence_score' in conf_filtered_iocs.columns:
                    conf_filtered_iocs = conf_filtered_iocs.sort_values('confidence_score', ascending=False)
                elif ioc_sort_by == "Confidence":
                    conf_filtered_iocs = conf_filtered_iocs.sort_values('confidence', ascending=False)
                elif ioc_sort_by == "First Seen":
                    conf_filtered_iocs = conf_filtered_iocs.sort_values('first_seen', ascending=False)
            
            # IOC type distribution
            type_counts = conf_filtered_iocs['type'].value_counts()
            fig_types = px.bar(
                x=type_counts.index,
                y=type_counts.values,
                title="IOC Distribution by Type",
                labels={'x': 'IOC Type', 'y': 'Count'}
            )
            st.plotly_chart(fig_types, use_container_width=True)
            
            # Threat type and source distribution
            col1, col2 = st.columns(2)
            
            with col1:
                threat_counts = conf_filtered_iocs['threat_type'].value_counts()
                fig_threats = px.pie(
                    values=threat_counts.values,
                    names=threat_counts.index,
                    title="Threat Type Distribution"
                )
                st.plotly_chart(fig_threats, use_container_width=True)
            
            with col2:
                if 'source' in conf_filtered_iocs.columns:
                    source_counts = conf_filtered_iocs['source'].value_counts()
                    fig_ioc_sources = px.bar(
                        x=source_counts.index,
                        y=source_counts.values,
                        title="IOCs by Source",
                        labels={'x': 'Source', 'y': 'Count'}
                    )
                    st.plotly_chart(fig_ioc_sources, use_container_width=True)
                else:
                    # Confidence distribution
                    if 'confidence_score' in conf_filtered_iocs.columns:
                        fig_conf = px.histogram(
                            conf_filtered_iocs,
                            x='confidence_score',
                            nbins=15,
                            title='IOC Confidence Distribution'
                        )
                        st.plotly_chart(fig_conf, use_container_width=True)
            
            # IOC timeline
            if 'first_seen' in conf_filtered_iocs.columns:
                ioc_timeline = conf_filtered_iocs.groupby(conf_filtered_iocs['first_seen'].dt.date).size().reset_index()
                ioc_timeline.columns = ['Date', 'Count']
                
                fig_timeline = px.line(
                    ioc_timeline,
                    x='Date',
                    y='Count',
                    title='New IOCs Over Time'
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
            
            # Detailed IOC table
            st.markdown("### 📋 Detailed IOC List")
            
            # Prepare display columns
            ioc_display_columns = ['indicator', 'type', 'threat_type', 'confidence', 'source', 'first_seen']
            if 'confidence_score' in conf_filtered_iocs.columns:
                ioc_display_columns.insert(-2, 'confidence_score')
            if 'risk_score' in conf_filtered_iocs.columns:
                ioc_display_columns.insert(-2, 'risk_score')
            
            # Format for display
            ioc_display = conf_filtered_iocs[ioc_display_columns].copy()
            if 'confidence_score' in ioc_display.columns:
                ioc_display['confidence_score'] = ioc_display['confidence_score'].round(2)
            
            st.dataframe(ioc_display, use_container_width=True)
            
            # Show statistics
            st.caption(f"Showing {len(conf_filtered_iocs)} indicators (filtered from {len(filtered_iocs)} total)")
            
        else:
            st.info("No indicators match your current filters.")
    
    with tab4:
        st.subheader("📊 Threat Intelligence Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk score distribution for vulnerabilities
            if not filtered_vulns.empty:
                fig_vuln_risk = px.histogram(
                    filtered_vulns,
                    x='risk_score',
                    nbins=20,
                    title='Vulnerability Risk Score Distribution',
                    color_discrete_sequence=['#dc3545']
                )
                st.plotly_chart(fig_vuln_risk, use_container_width=True)
        
        with col2:
            # Source reliability
            if not filtered_iocs.empty:
                source_confidence = filtered_iocs.groupby('source')['confidence'].mean().reset_index()
                fig_source = px.bar(
                    source_confidence,
                    x='source',
                    y='confidence',
                    title='Average Confidence by Source',
                    color='confidence',
                    color_continuous_scale='Viridis'
                )
                st.plotly_chart(fig_source, use_container_width=True)
        
        # Threat landscape overview
        st.markdown("### 🌐 Threat Landscape Overview")
        
        threat_summary = {
            'Total Vulnerabilities': len(data['vulnerabilities']) if not data['vulnerabilities'].empty else 0,
            'Critical/High Severity': len(data['vulnerabilities'][data['vulnerabilities']['severity'].isin(['Critical', 'High'])]) if not data['vulnerabilities'].empty else 0,
            'Total IOCs': len(data['indicators']) if not data['indicators'].empty else 0,
            'High Confidence IOCs': len(data['indicators'][data['indicators']['confidence'] >= 80]) if not data['indicators'].empty else 0,
            'Unique Threat Types': data['indicators']['threat_type'].nunique() if not data['indicators'].empty else 0,
            'Data Sources Active': len(set(data['indicators']['source'])) if not data['indicators'].empty else 0
        }
        
        summary_df = pd.DataFrame(list(threat_summary.items()), columns=['Metric', 'Value'])
        st.dataframe(summary_df, use_container_width=True, hide_index=True)
        
        # Risk posture over time (placeholder for future enhancement)
        st.markdown("### 📈 Risk Posture Trend (Coming Soon)")
        st.info("Historical risk tracking will be available in the next update.")
    
    with tab5:
        st.subheader("📰 Latest Cybersecurity News & Intelligence")
        
        # Enhanced sidebar filters for news
        with st.sidebar:
            st.markdown("---")
            st.markdown("**📰 News Filters**")
            
            # Freshness slider
            freshness_days = st.slider(
                "Freshness (days)",
                min_value=1,
                max_value=30,
                value=7,
                help="Show news from the last N days"
            )
            
            # Topics multiselect
            available_topics = [
                "All Topics",
                "CVE/Vulnerability", 
                "Ransomware",
                "Phishing", 
                "Data Breach",
                "APT/Nation-State",
                "Zero-Day",
                "Supply Chain",
                "Microsoft/Office 365",
                "VPN/Remote Access"
            ]
            
            selected_topics = st.multiselect(
                "Filter by Topics",
                available_topics[1:],  # Exclude "All Topics" from multiselect
                default=[],
                help="Select specific topics to focus on"
            )
        
        # Load news data
        try:
            with st.spinner("Loading latest cybersecurity intelligence..."):
                news_items = load_news()
            
            if not news_items:
                st.warning("No news items could be loaded. Please check your internet connection.")
            else:
                # Apply freshness filter
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=freshness_days)
                filtered_news = [
                    item for item in news_items 
                    if item.get('published_dt', datetime.min.replace(tzinfo=timezone.utc)) >= cutoff_date
                ]
                
                # Apply topic filters
                if selected_topics:
                    topic_map = {
                        "CVE/Vulnerability": ["cve:", "topic:vulnerability", "topic:0day"],
                        "Ransomware": ["topic:ransomware"],
                        "Phishing": ["topic:phishing"],
                        "Data Breach": ["topic:breach"],
                        "APT/Nation-State": ["actor:", "topic:apt"],
                        "Zero-Day": ["topic:0day"],
                        "Supply Chain": ["topic:supply-chain"],
                        "Microsoft/Office 365": ["vendor:microsoft", "vendor:office 365", "vendor:microsoft 365"],
                        "VPN/Remote Access": ["vendor:vpn", "vendor:rdp"]
                    }
                    
                    topic_filtered = []
                    for item in filtered_news:
                        item_tags = item.get('tags', [])
                        for selected_topic in selected_topics:
                            target_tags = topic_map.get(selected_topic, [])
                            if any(any(tag.startswith(target) for target in target_tags) for tag in item_tags):
                                topic_filtered.append(item)
                                break
                    filtered_news = topic_filtered
                
                # Display summary metrics (simplified)
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📰 Articles", len(filtered_news))
                with col2:
                    cve_count = len([item for item in filtered_news if any('cve:' in tag for tag in item.get('tags', []))])
                    st.metric("🔍 CVE Mentions", cve_count)
                with col3:
                    high_relevance = len([item for item in filtered_news if item.get('relevance_score', 0) >= 5])
                    st.metric("⚠️ High Relevance", high_relevance)
                
                st.markdown("---")
                
                # Display news items with enhanced formatting
                if filtered_news:
                    for i, item in enumerate(filtered_news):
                        with st.container():
                            # Title (bold headline)
                            st.markdown(f"**{item['title']}**")
                            
                            # Tags as chips (if any)
                            if item.get('tags'):
                                # Prioritize important tags for display
                                important_tags = []
                                other_tags = []
                                
                                for tag in item['tags'][:6]:  # Limit to 6 tags max
                                    if any(tag.startswith(prefix) for prefix in ['cve:', 'actor:', 'topic:ransomware', 'topic:0day', 'topic:breach']):
                                        important_tags.append(tag)
                                    else:
                                        other_tags.append(tag)
                                
                                display_tags = important_tags + other_tags[:6-len(important_tags)]
                                if display_tags:
                                    tag_display = " ".join([f"`{tag}`" for tag in display_tags])
                                    st.markdown(tag_display)
                            
                            # Summary (always visible, 2-3 lines) - preserving our earlier change
                            if item.get('summary_raw'):
                                summary_text = item['summary_raw'][:300] + "..." if len(item['summary_raw']) > 300 else item['summary_raw']
                                st.write(summary_text)
                            
                            # Read more link (source attribution only here)
                            if item.get('link'):
                                st.markdown(f"[🔗 Read full article]({item['link']})")
                            
                            # Date only (muted, at bottom) - preserving our earlier change
                            if item.get('published_dt'):
                                st.caption(f"📅 {item['published_dt'].strftime('%Y-%m-%d %H:%M UTC')}")
                            
                            # Relevance score for debugging (remove in production)
                            if item.get('relevance_score', 0) > 0:
                                st.caption(f"Relevance: {item['relevance_score']}")
                            
                            st.markdown("---")
                else:
                    st.info("No recent items matched your filters. Try adjusting the freshness slider or removing topic filters.")
                    
        except Exception as e:
            st.error(f"Error loading news: {str(e)}")
            st.info("Please check your internet connection and try refreshing the page.")
    
    with tab6:
        st.subheader("💥 Ransomware Groups Intelligence")
        
        # Ransomware-specific filters in sidebar (simplified)
        with st.sidebar:
            st.markdown("---")
            st.markdown("**💥 Ransomware Analysis**")
            
            rw_days = st.slider(
                "Analysis Window (days)",
                min_value=7,
                max_value=90,
                value=45,
                help="Analyze ransomware activity over the last N days"
            )
        
        try:
            with st.spinner("Analyzing ransomware group activity..."):
                # Get news items for analysis
                news_items = load_news()
                
                # Build ransomware groups data
                rw_payload = build_ransomware_groups(news_items, days_back=rw_days)
                
                # Save to SQLite (with fallback to in-memory)
                saved_to_db = clear_and_save(rw_payload)
                
                groups = rw_payload.get("groups", {})
                last_updated = rw_payload.get("last_updated", "Unknown")
                
                # Get all possible ransomware groups (detected + known profiles)
                all_group_names = set(groups.keys())
                profile_groups = ["LockBit", "ALPHV", "Cl0p", "BlackBasta", "Royal", "Play", "BianLian", 
                                "Akira", "Rhysida", "Scattered Spider", "Qilin", "RansomHub", "Cuba", 
                                "Medusa", "Conti", "Hive", "Maze", "Sodinokibi", "Ryuk", "DarkSide"]
                all_group_names.update(profile_groups)
                all_groups_list = sorted(list(all_group_names))
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🎯 Tracked Groups", len(all_groups_list))
            with col2:
                active_groups = len(groups)
                st.metric("📊 Recently Active", active_groups)
            with col3:
                total_victims = sum(len(group.get('victims', [])) for group in groups.values())
                st.metric("🏢 Victims Identified", total_victims)
            with col4:
                total_stories = sum(len(group.get('all_stories', [])) for group in groups.values())
                st.metric("📰 Total Coverage", total_stories)
            
            # Storage status
            storage_status = "💾 SQLite" if saved_to_db else "🧠 In-Memory"
            st.caption(f"Last updated: {last_updated} • Storage: {storage_status} • Analysis period: {rw_days} days")
            
            st.markdown("---")
            
            # Ransomware Group Cards Grid
            st.markdown("### 🃏 Ransomware Groups Directory")
            st.caption("Click on any group to view detailed threat intelligence profile")
            
            # Initialize session state for selected group
            if 'selected_ransomware_group' not in st.session_state:
                st.session_state.selected_ransomware_group = None
            
            # Create grid of clickable cards (4 columns)
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
                            # Determine if group has recent activity
                            is_active = group_name in groups
                            activity_score = group_data.get('activity_score', 0)
                            victim_count = len(group_data.get('victims', []))
                            last_seen = group_data.get('last_seen', 'No recent activity')
                            
                            # Create clickable button styled as a card
                            button_style = "🔥" if is_active else "💤"
                            button_text = f"{button_style} {group_name}"
                            
                            if st.button(
                                button_text,
                                key=f"group_{group_name}",
                                help=f"Click to view {group_name} profile",
                                use_container_width=True
                            ):
                                st.session_state.selected_ransomware_group = group_name
                            
                            # Show mini stats under button
                            if is_active:
                                st.caption(f"Activity: {activity_score} | Victims: {victim_count}")
                                st.caption(f"Last seen: {last_seen}")
                            else:
                                st.caption("No recent activity detected")
            
            st.markdown("---")
            
            # Profile Display Section
            if st.session_state.selected_ransomware_group:
                selected_group = st.session_state.selected_ransomware_group
                st.markdown(f"### 🔍 {selected_group} - Threat Intelligence Profile")
                
                # Get profile information
                profile = get_ransomware_profile(selected_group)
                group_data = groups.get(selected_group, {})
                
                # Profile overview in columns
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📋 Group Overview**")
                    st.write(f"**Description:** {profile['description']}")
                    st.write(f"**First Seen:** {profile['first_seen']}")
                    st.write(f"**Type:** {profile['type']}")
                    st.write(f"**Current Status:** {profile['status']}")
                    
                    if profile.get('notable_attacks'):
                        st.markdown("**🎯 Notable Attacks:**")
                        for attack in profile['notable_attacks']:
                            st.write(f"• {attack}")
                
                with col2:
                    st.markdown("**⚔️ Tactics & Targeting**")
                    st.markdown("**Primary Tactics:**")
                    for tactic in profile['tactics']:
                        st.write(f"• {tactic}")
                    
                    st.markdown("**Common Targets:**")
                    for target in profile['targets']:
                        st.write(f"• {target}")
                    
                    # Recent activity data if available
                    if group_data:
                        st.markdown("**📊 Recent Activity:**")
                        st.write(f"• **Last Activity:** {group_data.get('last_seen', 'Unknown')}")
                        st.write(f"• **News Mentions:** {group_data.get('activity_score', 0)}")
                        st.write(f"• **Identified Victims:** {len(group_data.get('victims', []))}")
                
                # Recent Intelligence Section
                if group_data:
                    st.markdown("---")
                    st.markdown(f"**📰 Recent Intelligence on {selected_group}**")
                    
                    # Display recent stories in tabs
                    if group_data.get('all_stories') or group_data.get('attack_stories') or group_data.get('victims'):
                        tab_stories, tab_attacks, tab_victims = st.tabs(["All News", "Attack Reports", "Recent Victims"])
                        
                        with tab_stories:
                            if group_data.get('all_stories'):
                                for story in group_data['all_stories'][:5]:
                                    st.write(f"**[{story['title']}]({story['link']})**")
                                    st.caption(f"Published: {story['published']}")
                                    if story.get('summary'):
                                        st.write(story['summary'])
                                    st.markdown("---")
                            else:
                                st.info("No recent news coverage detected")
                        
                        with tab_attacks:
                            if group_data.get('attack_stories'):
                                for story in group_data['attack_stories'][:3]:
                                    st.write(f"**[{story['title']}]({story['link']})**")
                                    st.caption(f"Published: {story['published']}")
                                    if story.get('summary'):
                                        st.write(story['summary'])
                                    st.markdown("---")
                            else:
                                st.info("No recent attack reports detected")
                        
                        with tab_victims:
                            if group_data.get('victims'):
                                victim_cols = st.columns(2)
                                for idx, victim in enumerate(group_data['victims'][:12]):
                                    col = victim_cols[idx % 2]
                                    with col:
                                        if victim.get('source'):
                                            st.write(f"**{victim['name']}**")
                                            st.caption(f"{victim['date']} - [Source]({victim['source']})")
                                        else:
                                            st.write(f"**{victim['name']}** - {victim['date']}")
                                
                                if len(group_data['victims']) > 12:
                                    st.caption(f"... and {len(group_data['victims']) - 12} more victims")
                            else:
                                st.info("No recent victims identified")
                    else:
                        st.info(f"No recent intelligence data available for {selected_group}")
                
                # Clear selection button
                if st.button("Clear Selection", key="clear_selection"):
                    st.session_state.selected_ransomware_group = None
                    st.rerun()
            else:
                st.info("👆 Select a ransomware group above to view detailed threat intelligence profile")
                
            # Legend
            st.markdown("---")
            st.caption("🔥 = Recently active groups with detected news coverage | 💤 = Groups with profiles but no recent activity")
            
            # Disclaimer
            st.info("""
            ⚠️ **Intelligence Disclaimer**: This analysis combines automated news parsing with curated threat intelligence profiles. 
            Information may include false positives and should be verified through official sources. 
            This tool provides situational awareness for threat intelligence purposes.
            """)
                    
        except Exception as e:
            st.error(f"Error analyzing ransomware activity: {str(e)}")
            st.info("Unable to analyze ransomware groups. This may be due to missing dependencies or network issues.")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ SME Threat Intelligence Platform MVP | Built with ❤️ for small businesses</p>
        <p>Enhanced Data Sources: CISA KEV & Advisories (Live), NVD (Live), AlienVault OTX (Live), Abuse.ch ThreatFox & URLhaus (Live), 8 News Sources (Live)</p>
        <p>Features: Confidence scoring, deduplication, multi-source correlation | Auto-refresh: Every hour</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
