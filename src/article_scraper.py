#!/usr/bin/env python3
"""
Article Content Scraper
Scrapes full article content and extracts summary and CVE details
"""

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from typing import Dict, Optional, List
import re
import warnings
from .cve_extractor import CVEExtractor
from .logger import logger

# Suppress XML parsing warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class ArticleContentScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.cve_extractor = CVEExtractor()
        self.timeout = 5  # Reduced timeout for faster failures
    
    def scrape_article(self, url: str) -> Optional[Dict]:
        """Scrape full article content from URL."""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style", "nav", "header", "footer", "aside"]):
                script.decompose()
            
            # Try to find main content
            content = self._extract_content(soup)
            
            if not content:
                return None
            
            # Extract summary (first 2-3 sentences)
            summary = self._extract_summary(content)
            
            # Extract all security IDs (CVE, MITRE ATT&CK) from content
            all_ids = self.cve_extractor.extract_all_ids(content)
            cves = all_ids.get('cves', [])
            mitre_attack = all_ids.get('mitre_attack', [])
            
            # Extract CVE details (skip NVD API calls during scraping for speed)
            # CVE details can be fetched later via web UI or background job
            cve_details = {}
            # Skip NVD API calls during scraping to improve performance
            # Uncomment below if you need CVE details immediately:
            # for cve in cves:
            #     cve_info = self.cve_extractor.get_cve_details(cve)
            #     if cve_info:
            #         cve_details[cve] = cve_info
            
            return {
                'content': content[:5000],  # Limit content length
                'summary': summary,
                'cve_numbers': cves,
                'mitre_attack_ids': mitre_attack,
                'cve_details': cve_details
            }
        except Exception as e:
            logger.error(f"Error scraping article {url}: {e}")
            return None
    
    def _extract_content(self, soup: BeautifulSoup) -> str:
        """Extract main content from article."""
        # Try common article content selectors
        selectors = [
            'article',
            '.article-content',
            '.post-content',
            '.entry-content',
            '.content',
            'main',
            '[role="main"]',
            '.article-body',
            '.post-body'
        ]
        
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                text = element.get_text(separator=' ', strip=True)
                if len(text) > 200:  # Minimum content length
                    return text
        
        # Fallback: get all paragraphs
        paragraphs = soup.find_all('p')
        if paragraphs:
            text = ' '.join([p.get_text(strip=True) for p in paragraphs])
            if len(text) > 200:
                return text
        
        # Last resort: get body text
        body = soup.find('body')
        if body:
            return body.get_text(separator=' ', strip=True)
        
        return ""
    
    def _extract_summary(self, content: str, max_sentences: int = 3) -> str:
        """Extract summary from content (first few sentences)."""
        # Split into sentences
        sentences = re.split(r'(?<=[.!?])\s+', content)
        
        # Filter out very short sentences
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        if not sentences:
            # Fallback: first 300 characters
            return content[:300] + "..." if len(content) > 300 else content
        
        # Take first few sentences
        summary_sentences = sentences[:max_sentences]
        summary = ' '.join(summary_sentences)
        
        # Limit length
        if len(summary) > 500:
            summary = summary[:500] + "..."
        
        return summary
