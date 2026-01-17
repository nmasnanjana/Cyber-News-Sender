#!/usr/bin/env python3
"""
CVE Number Extractor and NVD Integration
"""

import re
import requests
from typing import List, Dict, Optional
import time
from .utils import is_valid_cve as validate_cve

class CVEExtractor:
    def __init__(self):
        # CVE pattern: CVE-YYYY-NNNNN where YYYY is 4 digits and NNNNN is 4-7 digits
        self.cve_pattern = re.compile(r'CVE-(\d{4})-(\d{4,7})\b', re.IGNORECASE)
        # MITRE ATT&CK pattern: T#### or T####.### (e.g., T1055, T1055.001)
        self.mitre_attack_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE)
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def _is_valid_cve(self, cve: str) -> bool:
        """Validate CVE format using centralized utility function."""
        return validate_cve(cve)
    
    def extract_cves(self, text: str) -> List[str]:
        """Extract CVE numbers from text."""
        if not text:
            return []
        
        # Find all CVE matches
        matches = self.cve_pattern.finditer(text)
        cves = []
        for match in matches:
            year = match.group(1)
            number = match.group(2)
            cve = f"CVE-{year}-{number}".upper()
            # Validate the CVE
            if self._is_valid_cve(cve):
                cves.append(cve)
        
        # Remove duplicates and sort
        unique_cves = sorted(list(set(cves)))
        return unique_cves
    
    def extract_mitre_attack(self, text: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from text."""
        if not text:
            return []
        
        techniques = self.mitre_attack_pattern.findall(text)
        # Normalize to uppercase and remove duplicates
        unique_techniques = list(set([tech.upper() for tech in techniques]))
        return sorted(unique_techniques)
    
    def extract_all_ids(self, text: str) -> Dict[str, List[str]]:
        """Extract all security IDs (CVE, MITRE ATT&CK) from text."""
        return {
            'cves': self.extract_cves(text),
            'mitre_attack': self.extract_mitre_attack(text)
        }
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get CVE details from NVD API."""
        try:
            url = f"{self.nvd_api_base}?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('vulnerabilities') and len(data['vulnerabilities']) > 0:
                vuln = data['vulnerabilities'][0]['cve']
                
                # Extract CVSS score
                cvss_score = None
                cvss_severity = None
                if 'metrics' in vuln:
                    if 'cvssMetricV31' in vuln['metrics']:
                        metric = vuln['metrics']['cvssMetricV31'][0]
                        cvss_score = metric['cvssData']['baseScore']
                        cvss_severity = metric['cvssData']['baseSeverity']
                    elif 'cvssMetricV30' in vuln['metrics']:
                        metric = vuln['metrics']['cvssMetricV30'][0]
                        cvss_score = metric['cvssData']['baseScore']
                        cvss_severity = metric['cvssData']['baseSeverity']
                    elif 'cvssMetricV2' in vuln['metrics']:
                        metric = vuln['metrics']['cvssMetricV2'][0]
                        cvss_score = metric['cvssData']['baseScore']
                        cvss_severity = self._get_severity_v2(cvss_score)
                
                return {
                    'cve_id': cve_id,
                    'description': vuln.get('descriptions', [{}])[0].get('value', ''),
                    'cvss_score': cvss_score,
                    'cvss_severity': cvss_severity,
                    'published': vuln.get('published', ''),
                    'modified': vuln.get('lastModified', ''),
                    'references': [ref.get('url', '') for ref in vuln.get('references', [])]
                }
        except Exception as e:
            print(f"Error fetching CVE details for {cve_id}: {e}")
            return None
        
        return None
    
    def _get_severity_v2(self, score: float) -> str:
        """Convert CVSS v2 score to severity."""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_multiple_cve_details(self, cve_ids: List[str], delay=0.2) -> Dict[str, Dict]:
        """Get details for multiple CVEs with rate limiting."""
        results = {}
        for cve_id in cve_ids:
            details = self.get_cve_details(cve_id)
            if details:
                results[cve_id] = details
            time.sleep(delay)  # Rate limiting for NVD API
        return results
