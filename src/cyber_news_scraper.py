#!/usr/bin/env python3
"""
Cybersecurity News Scraper
Scrapes latest cybersecurity news, vulnerabilities, and exploitations from multiple sources.
"""

import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import time
import re
import os
from typing import List, Dict, Optional
from urllib.parse import urljoin
from .utils import normalize_url, sanitize_string, get_content_hash
import json
import xml.etree.ElementTree as ET
from urllib.robotparser import RobotFileParser
from difflib import SequenceMatcher
from .database import Database
from .cve_extractor import CVEExtractor
from .article_scraper import ArticleContentScraper
from .logger import logger

class CyberNewsScraper:
    def __init__(self, max_age_days: int = 3, use_db=True):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.today = datetime.now().date()
        self.max_age_days = max_age_days
        self.use_db = use_db
        
        # Initialize database (required for MySQL)
        if self.use_db:
            try:
                self.db = Database()
                self.cve_extractor = CVEExtractor()
                self.article_scraper = ArticleContentScraper()
                logger.info("Database, CVE extractor, and article scraper initialized")
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise  # Fail if database connection fails (MySQL is required)
        else:
            raise ValueError("Database is required. Set use_db=True")
        
        # Keywords to filter cybersecurity-related content
        self.cyber_keywords = [
            'cybersecurity', 'cyber security', 'vulnerability', 'vulnerabilities', 'exploit', 'exploitation',
            'ransomware', 'malware', 'phishing', 'hack', 'hacker', 'breach', 'data breach',
            'zero-day', 'zeroday', 'cve-', 'cve ', 'security flaw', 'security patch',
            'cyber attack', 'cyberattack', 'threat', 'threat actor', 'apt', 'backdoor',
            'trojan', 'virus', 'worm', 'spyware', 'ddos', 'sql injection', 'xss',
            'authentication bypass', 'privilege escalation', 'remote code execution',
            'information disclosure', 'security update', 'security advisory'
        ]
        
    def is_cybersecurity_related(self, text: str) -> bool:
        """Check if text is related to cybersecurity, vulnerabilities, or exploitations."""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.cyber_keywords)
    
    # History file methods removed - using MySQL database for duplicate tracking
    
    def is_recent_article(self, article: Dict) -> bool:
        """
        Check if article is recent enough to include.
        Returns True if:
        - Article has a date and it's within max_age_days
        - Article has no date - include it (assume it's from homepage and recent)
          but it will be tracked in history to avoid re-scraping
        """
        article_date = article.get('date')
        
        if article_date:
            try:
                # Parse date string
                if isinstance(article_date, str):
                    # Handle ISO format dates
                    date_str = article_date.split('T')[0]
                    date_obj = datetime.fromisoformat(date_str).date()
                else:
                    date_obj = article_date
                
                # Check if within max_age_days
                age = (self.today - date_obj).days
                if age < 0:
                    # Future date - include it
                    return True
                return age <= self.max_age_days
            except Exception as e:
                # If date parsing fails, exclude it to be safe
                return False
        else:
            # No date - if it's not in history, assume it's recent (from homepage)
            # It will be tracked in history so it won't be scraped again
            # This handles cases where sites don't provide dates but show recent articles
            return True
    
    def filter_recent_articles(self, articles: List[Dict]) -> List[Dict]:
        """Filter articles to only include recent ones and not previously scraped."""
        recent_articles = []
        
        for article in articles:
            url = article.get('url', '')
            if not url:
                continue
            
            # Check database for duplicates (MySQL)
            if self.db.article_exists(url, article.get('title', '')):
                continue
            
            # Check if article is recent
            if self.is_recent_article(article):
                recent_articles.append(article)
        
        return recent_articles
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL using centralized utility function."""
        return normalize_url(url)
    
    def clean_title(self, title: str) -> str:
        """Clean and normalize title text using utility function."""
        return sanitize_string(title, max_length=500)
    
    def title_similarity(self, title1: str, title2: str) -> float:
        """Calculate similarity ratio between two titles (0.0 to 1.0)."""
        clean1 = self.clean_title(title1).lower()
        clean2 = self.clean_title(title2).lower()
        
        # Use SequenceMatcher for similarity
        return SequenceMatcher(None, clean1, clean2).ratio()
    
    def remove_duplicates(self, articles: List[Dict], similarity_threshold: float = 0.85) -> List[Dict]:
        """
        Remove duplicates using multiple strategies:
        1. Exact URL matches (normalized)
        2. Similar titles (fuzzy matching)
        3. Clean malformed titles
        """
        if not articles:
            return []
        
        # First pass: Remove articles with malformed titles (too long, likely contains content)
        cleaned_articles = []
        for article in articles:
            title = article.get('title', '')
            # Skip if title is suspiciously long (likely contains article content)
            if len(title) > 300:
                continue
            # Skip if title has too many special characters or looks like content
            if title.count('\n') > 2 or title.count('  ') > 5:
                continue
            cleaned_articles.append(article)
        
        if not cleaned_articles:
            return []
        
        # Second pass: Normalize URLs and remove exact duplicates
        seen_urls = {}
        url_deduped = []
        
        for article in cleaned_articles:
            url = article.get('url', '')
            if not url:
                continue
            
            normalized_url = self.normalize_url(url)
            
            # If we've seen this URL before, keep the one with better title (shorter, cleaner)
            if normalized_url in seen_urls:
                existing = seen_urls[normalized_url]
                existing_title = existing.get('title', '')
                current_title = article.get('title', '')
                
                # Keep the one with shorter, cleaner title
                if len(self.clean_title(current_title)) < len(self.clean_title(existing_title)):
                    # Replace existing with current
                    url_deduped.remove(existing)
                    url_deduped.append(article)
                    seen_urls[normalized_url] = article
                # Otherwise keep existing
            else:
                seen_urls[normalized_url] = article
                url_deduped.append(article)
        
        # Third pass: Remove similar titles (same story from different sources)
        final_articles = []
        seen_titles = []
        
        for article in url_deduped:
            title = article.get('title', '')
            clean_title = self.clean_title(title)
            
            if not clean_title:
                continue
            
            # Check if this title is similar to any we've already seen
            is_duplicate = False
            for seen_title in seen_titles:
                similarity = self.title_similarity(clean_title, seen_title)
                if similarity >= similarity_threshold:
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                final_articles.append(article)
                seen_titles.append(clean_title)
        
        # Clean titles in final articles
        for article in final_articles:
            article['title'] = self.clean_title(article.get('title', ''))
        
        return final_articles
    
    def get_date_from_text(self, text: str) -> Optional[datetime]:
        """Extract date from text."""
        # Common date patterns
        patterns = [
            r'(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})',
            r'(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})',
            r'(\d{4})-(\d{2})-(\d{2})',
            r'(\d{1,2})/(\d{1,2})/(\d{4})',
        ]
        
        months = {
            'january': 1, 'february': 2, 'march': 3, 'april': 4,
            'may': 5, 'june': 6, 'july': 7, 'august': 8,
            'september': 9, 'october': 10, 'november': 11, 'december': 12
        }
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    if 'january' in pattern.lower() or 'february' in pattern.lower():
                        # Handle month name patterns
                        groups = match.groups()
                        if len(groups) == 3:
                            if groups[0].isdigit():
                                day, month_name, year = groups
                                month = months[month_name.lower()]
                            else:
                                month_name, day, year = groups
                                month = months[month_name.lower()]
                            return datetime(int(year), month, int(day)).date()
                    else:
                        # Handle numeric patterns
                        groups = match.groups()
                        if len(groups) == 3:
                            if '-' in text:
                                year, month, day = groups
                                return datetime(int(year), int(month), int(day)).date()
                            elif '/' in text:
                                month, day, year = groups
                                return datetime(int(year), int(month), int(day)).date()
                except:
                    continue
        return None
    
    def check_robots_txt(self, base_url: str) -> bool:
        """Check if scraping is allowed by robots.txt (ethical practice)."""
        try:
            rp = RobotFileParser()
            robots_url = urljoin(base_url, '/robots.txt')
            rp.set_url(robots_url)
            rp.read()
            return rp.can_fetch(self.session.headers['User-Agent'], base_url)
        except:
            # If robots.txt doesn't exist or can't be read, assume allowed
            # (many sites don't have strict robots.txt)
            return True
    
    def parse_rss_feed(self, rss_url: str, source_name: str) -> List[Dict]:
        """Parse RSS feed - RSS only, no HTML scraping."""
        articles = []
        try:
            response = self.session.get(rss_url, timeout=15)
            response.raise_for_status()
            
            # Parse XML
            root = ET.fromstring(response.content)
            
            # Handle both RSS 2.0 and Atom feeds
            items = root.findall('.//item')
            if not items:
                # Try Atom format
                items = root.findall('.//{http://www.w3.org/2005/Atom}entry')
            
            for item in items:
                # Get title - fix deprecation warning
                title_elem = item.find('title')
                if title_elem is None:
                    title_elem = item.find('{http://www.w3.org/2005/Atom}title')
                
                if title_elem is None or title_elem.text is None:
                    continue
                    
                title = title_elem.text.strip()
                
                if not title or len(title) < 10:
                    continue
                
                # Filter for cybersecurity content (skip for vendor advisories which are always security-related)
                vendor_sources = ['Cisco', 'Palo Alto', 'AWS', 'Google', 'Chrome', 'Cloudflare']
                if not any(vs in source_name for vs in vendor_sources):
                    if not self.is_cybersecurity_related(title):
                        continue
                
                # Get link
                link_elem = item.find('link')
                if link_elem is None:
                    link_elem = item.find('{http://www.w3.org/2005/Atom}link')
                
                if link_elem is None:
                    continue
                
                # Handle both RSS (text) and Atom (href attribute) link formats
                url = None
                if link_elem.text:
                    url = link_elem.text.strip()
                elif link_elem.get('href'):
                    url = link_elem.get('href').strip()
                
                if not url:
                    continue
                
                # Get date
                date_elem = item.find('pubDate')
                if date_elem is None:
                    date_elem = item.find('{http://www.w3.org/2005/Atom}published')
                if date_elem is None:
                    date_elem = item.find('{http://www.w3.org/2005/Atom}updated')
                
                article_date = None
                if date_elem is not None and date_elem.text:
                    try:
                        # Parse various date formats
                        date_str = date_elem.text.strip()
                        # Try ISO format first (Atom)
                        if 'T' in date_str:
                            try:
                                article_date = datetime.fromisoformat(date_str.replace('Z', '+00:00')).date()
                            except:
                                pass
                        else:
                            # Try common RSS date formats
                            for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S %Z', '%Y-%m-%d', '%d %b %Y', '%a, %d %b %Y']:
                                try:
                                    article_date = datetime.strptime(date_str, fmt).date()
                                    break
                                except:
                                    continue
                    except:
                        pass
                
                # REQUIRE: title, url, and date must all be present (not null)
                if not title or not url or article_date is None:
                    continue  # Skip articles missing required fields
                
                # Try to get description/summary from RSS feed
                description = None
                desc_elem = item.find('description')
                if desc_elem is None:
                    desc_elem = item.find('{http://www.w3.org/2005/Atom}summary')
                if desc_elem is None:
                    desc_elem = item.find('{http://www.w3.org/2005/Atom}content')
                
                if desc_elem is not None and desc_elem.text:
                    # Clean HTML from description
                    desc_text = BeautifulSoup(desc_elem.text, 'html.parser').get_text(strip=True)
                    if desc_text and len(desc_text) > 50:
                        # Use first 2-3 sentences as summary
                        sentences = re.split(r'(?<=[.!?])\s+', desc_text)
                        description = ' '.join(sentences[:3])[:500]
                
                # Only include recent articles (within max_age_days)
                if article_date >= self.today - timedelta(days=self.max_age_days):
                    articles.append({
                        'title': title,
                        'url': url,
                        'source': source_name,
                        'date': article_date.isoformat(),  # Always present (not null)
                        'summary': description  # May be None, will be filled later
                    })
            
            return articles[:30]  # Limit results per source
            
        except Exception as e:
            logger.error(f"Error parsing RSS feed {rss_url}: {e}")
            return []
    
    # RSS-only scraping methods (no HTML scraping)
    
    def scrape_bleepingcomputer(self) -> List[Dict]:
        """Scrape cybersecurity news from BleepingComputer (RSS only)."""
        rss_url = "https://www.bleepingcomputer.com/feed/"
        return self.parse_rss_feed(rss_url, 'BleepingComputer')
    
    def scrape_threatpost(self) -> List[Dict]:
        """Scrape cybersecurity news from ThreatPost (RSS only)."""
        rss_url = "https://threatpost.com/feed/"
        return self.parse_rss_feed(rss_url, 'ThreatPost')
    
    def scrape_hackernews(self) -> List[Dict]:
        """Scrape cybersecurity news from The Hacker News (RSS only)."""
        rss_url = "https://feeds.feedburner.com/TheHackersNews"
        return self.parse_rss_feed(rss_url, 'The Hacker News')
    
    def scrape_cyberexpress(self) -> List[Dict]:
        """Scrape cybersecurity news from The Cyber Express (RSS only)."""
        rss_url = "https://thecyberexpress.com/feed/"
        return self.parse_rss_feed(rss_url, 'The Cyber Express')
    
    def scrape_cisco_psirt(self) -> List[Dict]:
        """Scrape Cisco PSIRT Security Advisories (RSS only)."""
        rss_url = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
        return self.parse_rss_feed(rss_url, 'Cisco PSIRT')
    
    def scrape_cisco_csaf(self) -> List[Dict]:
        """Scrape Cisco CSAF Security Advisories (RSS only)."""
        rss_url = "https://sec.cloudapps.cisco.com/security/center/csaf_20.xml"
        return self.parse_rss_feed(rss_url, 'Cisco CSAF')
    
    def scrape_cisco_event_responses(self) -> List[Dict]:
        """Scrape Cisco Event Responses (RSS only)."""
        rss_url = "https://sec.cloudapps.cisco.com/security/center/eventResponses_20.xml"
        return self.parse_rss_feed(rss_url, 'Cisco Event Responses')
    
    def scrape_palo_alto(self) -> List[Dict]:
        """Scrape Palo Alto Networks Security Advisories (RSS only)."""
        rss_url = "https://security.paloaltonetworks.com/rss.xml"
        return self.parse_rss_feed(rss_url, 'Palo Alto Networks')
    
    def scrape_aws_security(self) -> List[Dict]:
        """Scrape AWS Security Bulletins (RSS only)."""
        rss_url = "https://aws.amazon.com/security/security-bulletins/feed/"
        return self.parse_rss_feed(rss_url, 'AWS Security')
    
    def scrape_google_security(self) -> List[Dict]:
        """Scrape Google Online Security Blog (RSS only)."""
        rss_url = "https://security.googleblog.com/feeds/posts/default?alt=rss"
        return self.parse_rss_feed(rss_url, 'Google Security')
    
    def scrape_chrome_releases(self) -> List[Dict]:
        """Scrape Chrome Releases (RSS only)."""
        rss_url = "https://chromereleases.googleblog.com/feeds/posts/default?alt=rss"
        return self.parse_rss_feed(rss_url, 'Chrome Releases')
    
    def scrape_cloudflare(self) -> List[Dict]:
        """Scrape Cloudflare Changelog (RSS only)."""
        rss_url = "https://developers.cloudflare.com/changelog/rss/index.xml"
        return self.parse_rss_feed(rss_url, 'Cloudflare')
    
    def scrape_sans_isc(self) -> List[Dict]:
        """Scrape SANS Internet Storm Center (RSS only)."""
        rss_url = "https://isc.sans.edu/rssfeed_full.xml"
        return self.parse_rss_feed(rss_url, 'SANS ISC')
    
    def scrape_krebs(self) -> List[Dict]:
        """Scrape Krebs on Security (RSS only)."""
        rss_url = "https://krebsonsecurity.com/feed/"
        return self.parse_rss_feed(rss_url, 'Krebs on Security')
    
    def scrape_schneier(self) -> List[Dict]:
        """Scrape Schneier on Security (RSS only)."""
        rss_url = "https://www.schneier.com/feed/atom/"
        return self.parse_rss_feed(rss_url, 'Schneier on Security')
    
    def scrape_kaspersky(self) -> List[Dict]:
        """Scrape Kaspersky Securelist (RSS only)."""
        rss_url = "https://securelist.com/feed/"
        return self.parse_rss_feed(rss_url, 'Kaspersky Securelist')
    
    def scrape_all(self) -> List[Dict]:
        """Scrape all sources using RSS feeds only and return combined results."""
        print("Starting cybersecurity news scraping...")
        print(f"Target date: {self.today}\n")
        print("Note: Using RSS feeds only for legal compliance\n")
        
        all_articles = []
        
        # News sources
        sources = [
            ("BleepingComputer", self.scrape_bleepingcomputer),
            ("ThreatPost", self.scrape_threatpost),
            ("The Hacker News", self.scrape_hackernews),
            ("The Cyber Express", self.scrape_cyberexpress),
        ]
        
        # Vendor advisories
        vendor_sources = [
            ("Cisco PSIRT", self.scrape_cisco_psirt),
            ("Cisco CSAF", self.scrape_cisco_csaf),
            ("Cisco Event Responses", self.scrape_cisco_event_responses),
            ("Palo Alto Networks", self.scrape_palo_alto),
            ("AWS Security", self.scrape_aws_security),
            ("Google Security", self.scrape_google_security),
            ("Chrome Releases", self.scrape_chrome_releases),
            ("Cloudflare", self.scrape_cloudflare),
        ]
        
        # Research & threat intel
        research_sources = [
            ("SANS ISC", self.scrape_sans_isc),
            ("Krebs on Security", self.scrape_krebs),
            ("Schneier on Security", self.scrape_schneier),
            ("Kaspersky Securelist", self.scrape_kaspersky),
        ]
        
        # Scrape all sources
        for name, scraper_func in sources + vendor_sources + research_sources:
            print(f"Scraping {name} (RSS feed)...")
            try:
                articles = scraper_func()
                all_articles.extend(articles)
                logger.info(f"{name}: Found {len(articles)} articles")
                print(f"Found {len(articles)} articles\n")
            except Exception as e:
                logger.error(f"Error scraping {name}: {e}")
                print(f"Error: {e}\n")
            time.sleep(1)  # Be respectful with requests
        
        # Advanced duplicate removal
        print("Removing duplicates...")
        print(f"Articles before deduplication: {len(all_articles)}")
        unique_articles = self.remove_duplicates(all_articles)
        print(f"Articles after deduplication: {len(unique_articles)}")
        print(f"Removed {len(all_articles) - len(unique_articles)} duplicates\n")
        
        # Filter for recent articles and exclude previously scraped
        print("Filtering for recent articles and checking history...")
        print(f"Articles before date/history filtering: {len(unique_articles)}")
        recent_articles = self.filter_recent_articles(unique_articles)
        print(f"Articles after filtering (recent + not previously scraped): {len(recent_articles)}")
        print(f"Filtered out {len(unique_articles) - len(recent_articles)} old/previously scraped articles\n")
        
        # Save to database (optimized batch insert)
        if recent_articles:
            if self.use_db:
                logger.info(f"Processing {len(recent_articles)} articles for database")
                
                # Prepare all articles for batch insert
                articles_to_save = []
                
                for article in recent_articles:
                    title = article.get('title', '')
                    url = article.get('url', '')
                    source = article.get('source', '')
                    date_str = article.get('date')
                    
                    # Parse date
                    date_obj = None
                    if date_str:
                        try:
                            date_obj = datetime.fromisoformat(date_str.split('T')[0])
                        except:
                            pass
                    
                    # Extract security IDs from title
                    title_ids = self.cve_extractor.extract_all_ids(title)
                    cve_numbers = title_ids.get('cves', [])
                    mitre_attack_ids = title_ids.get('mitre_attack', [])
                    
                    # Determine categories
                    categories = self._categorize_article(title)
                    
                    # Get summary from RSS if available, otherwise scrape
                    summary = article.get('summary')  # May be from RSS description
                    content = None
                    cve_details = None
                    article_cves = cve_numbers.copy() if cve_numbers else []
                    article_mitre = mitre_attack_ids.copy() if mitre_attack_ids else []
                    
                    # Scrape article content for full summary, content, and security IDs
                    # Only scrape if RSS didn't provide a good summary (optimization)
                    should_scrape = not summary or len(summary) < 100
                    
                    if should_scrape:
                        try:
                            logger.debug(f"Scraping article content: {url}")
                            article_data = self.article_scraper.scrape_article(url)
                            if article_data:
                                # Use scraped summary if RSS didn't provide one or if scraped is better
                                scraped_summary = article_data.get('summary')
                                if scraped_summary and (not summary or len(scraped_summary) > len(summary)):
                                    summary = scraped_summary
                                
                                content = article_data.get('content')
                                
                                # Merge CVEs from title and content
                                if article_data.get('cve_numbers'):
                                    article_cves = list(set(cve_numbers + article_data.get('cve_numbers', [])))
                                
                                # Merge MITRE ATT&CK IDs from title and content
                                if article_data.get('mitre_attack_ids'):
                                    article_mitre = list(set(mitre_attack_ids + article_data.get('mitre_attack_ids', [])))
                                
                                cve_details = article_data.get('cve_details', {})
                        except Exception as e:
                            logger.debug(f"Could not scrape article content for {url}: {e}")
                    else:
                        logger.debug(f"Skipping content scrape for {url} (RSS summary sufficient)")
                    
                    # Small delay only if we scraped
                    if should_scrape:
                        time.sleep(0.2)  # Minimal delay
                    
                    # Ensure summary exists (create from title if missing)
                    if not summary:
                        summary = f"{title[:200]}..." if len(title) > 200 else title
                    
                    # Prepare article data for batch insert
                    articles_to_save.append({
                        'title': title,
                        'url': url,
                        'source': source,
                        'date': date_obj,
                        'cve_numbers': article_cves if article_cves else None,
                        'mitre_attack_ids': article_mitre if article_mitre else None,
                        'categories': categories if categories else None,
                        'summary': summary,
                        'content': content,
                        'cve_details': cve_details
                    })
                
                # Batch insert all articles at once
                try:
                    saved_count = len(self.db.add_articles_batch(articles_to_save))
                    logger.info(f"Successfully saved {saved_count} articles to database")
                    print(f"Saved {saved_count} articles to database\n")
                except Exception as e:
                    logger.error(f"Error in batch save: {e}")
                    # Fallback: try individual saves
                    saved_count = 0
                    for article_data in articles_to_save:
                        try:
                            self.db.add_article(**article_data)
                            saved_count += 1
                        except Exception as e2:
                            logger.error(f"Error saving individual article: {e2}")
                    logger.info(f"Saved {saved_count} articles (fallback mode)")
            
            # Update in-memory history (database is source of truth)
            for article in recent_articles:
                normalized_url = self.normalize_url(article.get('url', ''))
                self.scraped_urls.add(normalized_url)
        
        return recent_articles
    
    def _categorize_article(self, title: str) -> List[str]:
        """Categorize article based on keywords."""
        title_lower = title.lower()
        categories = []
        
        if any(kw in title_lower for kw in ['ransomware', 'lockbit', 'conti']):
            categories.append('ransomware')
        if any(kw in title_lower for kw in ['apt', 'nation-state', 'state-sponsored']):
            categories.append('apt')
        if any(kw in title_lower for kw in ['zero-day', 'zeroday', '0-day']):
            categories.append('zero-day')
        if any(kw in title_lower for kw in ['cve-', 'vulnerability', 'vulnerabilities']):
            categories.append('vulnerability')
        if any(kw in title_lower for kw in ['exploit', 'exploitation', 'poc']):
            categories.append('exploit')
        if any(kw in title_lower for kw in ['breach', 'data breach', 'leak']):
            categories.append('breach')
        if any(kw in title_lower for kw in ['malware', 'trojan', 'virus']):
            categories.append('malware')
        if any(kw in title_lower for kw in ['iot', 'industrial', 'scada']):
            categories.append('iot')
        
        return categories
    
    def save_to_json(self, articles: List[Dict], filename: str = "cyber_news.json"):
        """Save articles to JSON file."""
        # Use data directory if in Docker, otherwise current directory
        if os.path.exists('/app/data'):
            filename = f'/app/data/{os.path.basename(filename)}'
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(articles, f, indent=2, ensure_ascii=False)
        print(f"\nArticles saved to {filename}")
    
    def print_articles(self, articles: List[Dict]):
        """Print articles in a readable format."""
        print("\n" + "="*80)
        print("CYBERSECURITY NEWS - VULNERABILITIES & EXPLOITATIONS")
        print("="*80 + "\n")
        
        for i, article in enumerate(articles, 1):
            print(f"{i}. {article['title']}")
            print(f"   Source: {article['source']}")
            print(f"   URL: {article['url']}")
            if article['date']:
                print(f"   Date: {article['date']}")
            print()


# This is a module - use main.py as entry point
