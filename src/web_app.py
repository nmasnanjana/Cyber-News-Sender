#!/usr/bin/env python3
"""
Web Dashboard for Cyber News Sender
Enhanced UI with graphs, summaries, and CVE details
"""

from flask import Flask, render_template_string, jsonify, request, Response, send_from_directory
from .database import Database, Article, Recipient
from datetime import datetime, timedelta
import json
import os
import logging

# Load environment variables
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

# Import security and utility modules
from .security import add_security_headers, rate_limit, validate_input, sanitize_json_input, GDPRCompliance
from .utils import is_valid_cve, sanitize_email, escape_html, sanitize_string

# Get the project root directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STATIC_FOLDER = os.path.join(PROJECT_ROOT, 'static')

app = Flask(__name__, static_folder=STATIC_FOLDER)
db = Database()
logger = logging.getLogger('cyber_news')

# Add security headers to all responses
@app.after_request
def after_request(response):
    """Add security headers to all responses."""
    return add_security_headers(response)

# Enhanced HTML template with graphs and better layout
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Cyber News Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8f9fa;
            color: #212529;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 20px 40px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header-content {
            display: flex;
            align-items: center;
            gap: 40px;
            flex: 1;
        }
        .header h1 {
            font-size: 26px;
            font-weight: 700;
            margin: 0;
            letter-spacing: -0.5px;
        }
        .nav-links {
            display: flex;
            gap: 4px;
            align-items: center;
        }
        .nav-link {
            color: rgba(255, 255, 255, 0.85);
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 6px;
            transition: all 0.2s;
            font-size: 14px;
            font-weight: 500;
            background: transparent;
            border: 1px solid transparent;
        }
        .nav-link:hover {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        .nav-link.active {
            background: rgba(255, 255, 255, 0.15);
            color: white;
            border-color: rgba(255, 255, 255, 0.2);
        }
        .subscribe-btn {
            background: #ffffff;
            color: #1e3c72;
            border: none;
            padding: 10px 24px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .subscribe-btn:hover {
            background: #f8f9fa;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        @media (max-width: 1400px) {
            .stats {
                grid-template-columns: repeat(3, 1fr);
            }
        }
        @media (max-width: 768px) {
            .stats {
                grid-template-columns: 1fr;
            }
        }
        .stat-box {
            background: #ffffff;
            padding: 20px;
            border: none;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: all 0.2s;
            position: relative;
            overflow: hidden;
            height: 120px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .stat-box::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 5px;
            height: 100%;
            background: linear-gradient(180deg, #2196f3 0%, #1976d2 100%);
        }
        .stat-box:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 24px rgba(33, 150, 243, 0.15);
        }
        .stat-box h3 {
            font-size: 11px;
            color: #6c757d;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        .stat-box .number {
            font-size: 36px;
            font-weight: 700;
            color: #212529;
            line-height: 1;
            margin-bottom: 6px;
        }
        .stat-box .subtitle {
            font-size: 11px;
            color: #868e96;
            margin-top: 0;
            font-weight: 400;
        }
        .heatmaps-section {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 30px;
            width: 100%;
        }
        @media (max-width: 1200px) {
            .heatmaps-section {
                grid-template-columns: 1fr;
            }
        }
        .charts-section {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
            width: 100%;
        }
        @media (max-width: 1200px) {
            .charts-section {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        @media (max-width: 768px) {
            .charts-section {
                grid-template-columns: 1fr;
            }
        }
        .chart-box {
            background: #ffffff;
            padding: 20px;
            border: none;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            height: 320px;
            transition: all 0.2s;
            display: flex;
            flex-direction: column;
            width: 100%;
            overflow: hidden;
        }
        .chart-box:hover {
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }
        .chart-box h3 {
            font-size: 14px;
            color: #212529;
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e9ecef;
            font-weight: 600;
            flex-shrink: 0;
        }
        .chart-box canvas {
            flex: 1;
            min-height: 0;
            max-height: calc(100% - 50px);
            width: 100% !important;
        }
        .heatmap-container {
            background: #ffffff;
            padding: 20px;
            border: none;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: all 0.2s;
            height: 320px;
            display: flex;
            flex-direction: column;
            width: 100%;
        }
        .heatmap-container:hover {
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }
        .heatmap-container h3 {
            font-size: 14px;
            color: #212529;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid #e9ecef;
            font-weight: 600;
            flex-shrink: 0;
        }
        .heatmap-container .heatmap {
            overflow-y: auto;
            padding: 0;
            display: flex;
            flex-wrap: wrap;
            align-content: flex-start;
            align-items: flex-start;
            gap: 8px;
            flex: 0 1 auto;
            max-height: calc(100% - 60px);
        }
        .heatmap-item {
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: white;
            transition: all 0.15s;
            cursor: pointer;
            border: none;
            display: inline-block;
            text-decoration: none;
            margin: 4px;
        }
        .heatmap-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        .heatmap-item.size-1 { background: #e3f2fd; color: #1565c0; }
        .heatmap-item.size-2 { background: #bbdefb; color: #0d47a1; }
        .heatmap-item.size-3 { background: #90caf9; color: #0d47a1; }
        .heatmap-item.size-4 { background: #64b5f6; color: white; }
        .heatmap-item.size-5 { background: #42a5f5; color: white; }
        .heatmap-item.size-6 { background: #2196f3; color: white; }
        .heatmap-item.size-7 { background: #1976d2; color: white; }
        .filter-bar {
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .filter-bar input, .filter-bar select {
            padding: 10px;
            margin-right: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .btn {
            padding: 10px 20px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }
        .btn:hover {
            background: #2980b9;
        }
        .section-title {
            font-size: 20px;
            color: #2c3e50;
            margin: 30px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }
        .articles {
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .article-item {
            padding: 20px;
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }
        .article-item:hover {
            background: #f9f9f9;
        }
        .article-item:last-child {
            border-bottom: none;
        }
        .article-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .article-title a {
            color: #2c3e50;
            text-decoration: none;
        }
        .article-title a:hover {
            color: #3498db;
            text-decoration: underline;
        }
        .article-summary {
            color: #555;
            margin: 10px 0;
            line-height: 1.6;
            font-size: 14px;
        }
        .article-meta {
            font-size: 12px;
            color: #666;
            margin-top: 10px;
        }
        .cve-badge {
            display: inline-block;
            background: #e74c3c;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            margin: 5px 5px 5px 0;
            font-weight: 600;
        }
        .cve-badge a {
            color: white;
            text-decoration: none;
        }
        .cve-badge a:hover {
            text-decoration: underline;
        }
        .category-tag {
            display: inline-block;
            background: #95a5a6;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            margin-right: 5px;
        }
        .read-more {
            color: #3498db;
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
        }
        .read-more:hover {
            text-decoration: underline;
        }
        .cve-details {
            margin-top: 10px;
            padding: 10px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
            font-size: 12px;
        }
        .cve-details strong {
            color: #856404;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            animation: fadeIn 0.2s;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        .modal-content {
            background-color: #ffffff;
            margin: 15% auto;
            padding: 30px;
            border-radius: 12px;
            width: 90%;
            max-width: 450px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
            animation: slideDown 0.3s;
        }
        @keyframes slideDown {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        .modal-header {
            margin-bottom: 20px;
        }
        .modal-header h2 {
            font-size: 24px;
            color: #212529;
            margin-bottom: 8px;
        }
        .modal-header p {
            font-size: 14px;
            color: #6c757d;
            margin: 0;
        }
        .modal-body {
            margin-bottom: 20px;
        }
        .modal-body input {
            width: 100%;
            padding: 12px;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            font-size: 14px;
            box-sizing: border-box;
        }
        .modal-body input:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }
        .modal-footer {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
        .modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .modal-btn-primary {
            background: #3498db;
            color: white;
        }
        .modal-btn-primary:hover {
            background: #2980b9;
        }
        .modal-btn-secondary {
            background: #95a5a6;
            color: white;
        }
        .modal-btn-secondary:hover {
            background: #7f8c8d;
        }
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 6px;
            margin-top: 10px;
            font-size: 14px;
            display: none;
        }
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 6px;
            margin-top: 10px;
            font-size: 14px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>Cyber News Dashboard</h1>
            <div class="nav-links">
                <a href="/" class="nav-link active">Dashboard</a>
                <a href="/archive" class="nav-link">Older News</a>
            </div>
        </div>
        <button class="subscribe-btn" onclick="openSubscribeModal()">Subscribe</button>
    </div>
    
    <!-- Subscribe Modal -->
    <div id="subscribeModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Subscribe to Daily Cyber News</h2>
                <p>Get the latest cybersecurity news, vulnerabilities, and exploitations delivered to your inbox daily at 9:30 AM IST</p>
            </div>
            <div class="modal-body">
                <input type="email" id="subscribeEmail" placeholder="Enter your email address" required>
                <div id="subscribeSuccess" class="success-message"></div>
                <div id="subscribeError" class="error-message"></div>
            </div>
            <div class="modal-footer">
                <button class="modal-btn modal-btn-secondary" onclick="closeSubscribeModal()">Cancel</button>
                <button class="modal-btn modal-btn-primary" onclick="subscribeEmail()">Subscribe</button>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="stats">
            <div class="stat-box">
                <h3>Total Articles</h3>
                <div class="number" id="total-articles">-</div>
                <div class="subtitle">All time</div>
            </div>
            <div class="stat-box">
                <h3>Today's Articles</h3>
                <div class="number" id="today-articles">-</div>
                <div class="subtitle">Last 24 hours</div>
            </div>
            <div class="stat-box">
                <h3>Yesterday's Articles</h3>
                <div class="number" id="yesterday-articles">-</div>
                <div class="subtitle">Previous day</div>
            </div>
            <div class="stat-box">
                <h3>Unique CVEs</h3>
                <div class="number" id="unique-cves">-</div>
                <div class="subtitle">Last 7 days</div>
            </div>
            <div class="stat-box">
                <h3>Active Recipients</h3>
                <div class="number" id="recipients">-</div>
                <div class="subtitle">Email list</div>
            </div>
        </div>
        
        <div class="heatmaps-section">
            <div class="heatmap-container">
                <h3>Top Categories (Last 7 Days)</h3>
                <div class="heatmap" id="categoryHeatmap">
                    <div class="loading">Loading categories...</div>
                </div>
            </div>
            
            <div class="heatmap-container">
                <h3>Top CVEs (Last 7 Days)</h3>
                <div class="heatmap" id="cveHeatmap">
                    <div class="loading">Loading CVEs...</div>
                </div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-box">
                <h3>Articles by Source (Last 7 Days)</h3>
                <canvas id="sourceChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Articles by Category (Last 7 Days)</h3>
                <canvas id="categoryChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Articles Over Time (Last 7 Days)</h3>
                <canvas id="timeChart"></canvas>
            </div>
        </div>
        
        <div class="filter-bar">
            <input type="text" id="search" placeholder="Search articles..." onkeyup="filterArticles()">
            <select id="source-filter" onchange="filterArticles()">
                <option value="">All Sources</option>
            </select>
            <select id="category-filter" onchange="filterArticles()">
                <option value="">All Categories</option>
                <option value="vulnerability">Vulnerability</option>
                <option value="exploit">Exploit</option>
                <option value="ransomware">Ransomware</option>
                <option value="apt">APT</option>
                <option value="zero-day">Zero-Day</option>
            </select>
            <button class="btn" onclick="loadArticles()">Refresh</button>
        </div>
        
        <h2 class="section-title">Today's News</h2>
        <div class="articles" id="today-articles-container">
            <p>Loading articles...</p>
        </div>
        
        <h2 class="section-title">Yesterday's News</h2>
        <div class="articles" id="yesterday-articles-container">
            <p>Loading articles...</p>
        </div>
    </div>
    
    <script>
        let sourceChart, categoryChart, timeChart;
        
        function loadStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total-articles').textContent = data.total_articles || 0;
                    document.getElementById('today-articles').textContent = data.today_articles || 0;
                    document.getElementById('yesterday-articles').textContent = data.yesterday_articles || 0;
                    document.getElementById('unique-cves').textContent = data.unique_cves || 0;
                    document.getElementById('recipients').textContent = data.recipients || 0;
                    
                    // Update charts and heatmaps
                    updateCharts(data);
                    updateHeatmaps(data);
                });
        }
        
        function updateHeatmaps(data) {
            // Category heatmap - make clickable
            const categoryHeatmap = document.getElementById('categoryHeatmap');
            if (data.category_heatmap && data.category_heatmap.length > 0) {
                let html = '';
                // Calculate max count for sizing
                const maxCount = Math.max(...data.category_heatmap.map(item => item.count));
                data.category_heatmap.forEach(item => {
                    // Size based on relative count (1-7 scale)
                    const size = Math.min(7, Math.max(1, Math.ceil((item.count / maxCount) * 7)));
                    const categoryUrl = `/archive?category=${encodeURIComponent(item.name)}`;
                    html += `<a href="${categoryUrl}" class="heatmap-item size-${size}" title="${item.name}: ${item.count} articles in last 7 days">${item.name}</a>`;
                });
                categoryHeatmap.innerHTML = html;
            } else {
                categoryHeatmap.innerHTML = '<p style="color: #868e96; padding: 24px; text-align: center; font-size: 14px;">No category data for last 7 days</p>';
            }
            
            // CVE heatmap - show all CVEs (not just top 20) - validate CVE format strictly
            function isValidCVE(cve) {
                if (!cve || typeof cve !== 'string') return false;
                
                cve = cve.toUpperCase().trim();
                
                // Must start with CVE-
                if (!cve.startsWith('CVE-')) return false;
                
                // CVE pattern: CVE-YYYY-NNNNN where YYYY is 4 digits and NNNNN is 4-7 digits
                const pattern = /^CVE-(\d{4})-(\d{4,7})$/i;
                const match = cve.match(pattern);
                if (!match) return false;
                
                const year = parseInt(match[1]);
                const number = match[2];
                
                // Year should be between 1999 and 2099
                if (year < 1999 || year > 2099) return false;
                
                // Number should be exactly 4-7 digits
                if (number.length < 4 || number.length > 7) return false;
                
                // Ensure exact match (no extra characters)
                const expectedFormat = `CVE-${year.toString().padStart(4, '0')}-${number}`;
                if (cve !== expectedFormat) return false;
                
                return true;
            }
            
            const cveHeatmap = document.getElementById('cveHeatmap');
            if (data.cve_heatmap && data.cve_heatmap.length > 0) {
                // Filter out invalid CVEs
                const validCves = data.cve_heatmap.filter(item => isValidCVE(item.name));
                
                if (validCves.length === 0) {
                    cveHeatmap.innerHTML = '<p style="color: #868e96; padding: 24px; text-align: center; font-size: 14px;">No valid CVE data for last 7 days</p>';
                    return;
                }
                
                let html = '';
                // Calculate max count for sizing
                const maxCount = Math.max(...validCves.map(item => item.count));
                validCves.forEach(item => {
                    // Size based on relative count (1-7 scale)
                    const size = Math.min(7, Math.max(1, Math.ceil((item.count / maxCount) * 7)));
                    html += `<a href="https://nvd.nist.gov/vuln/detail/${item.name}" target="_blank" class="heatmap-item size-${size}" title="${item.name}: ${item.count} articles in last 7 days">${item.name}</a>`;
                });
                cveHeatmap.innerHTML = html;
            } else {
                cveHeatmap.innerHTML = '<p style="color: #868e96; padding: 24px; text-align: center; font-size: 14px;">No CVE data for last 7 days</p>';
            }
        }
        
        function updateCharts(data) {
            // Source chart
            if (sourceChart) sourceChart.destroy();
            const sourceCtx = document.getElementById('sourceChart').getContext('2d');
            sourceChart = new Chart(sourceCtx, {
                type: 'doughnut',
                data: {
                    labels: data.source_labels || [],
                    datasets: [{
                        data: data.source_data || [],
                        backgroundColor: ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#1abc9c', '#34495e', '#95a5a6', '#16a085']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    aspectRatio: 1.5,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'bottom',
                            labels: {
                                boxWidth: 10,
                                padding: 6,
                                font: {
                                    size: 9
                                },
                                usePointStyle: true
                            }
                        }
                    }
                }
            });
            
            // Category chart
            if (categoryChart) categoryChart.destroy();
            const categoryCtx = document.getElementById('categoryChart').getContext('2d');
            categoryChart = new Chart(categoryCtx, {
                type: 'bar',
                data: {
                    labels: data.category_labels || [],
                    datasets: [{
                        label: 'Articles',
                        data: data.category_data || [],
                        backgroundColor: '#3498db'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    aspectRatio: 1.5,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
            
            // Time chart
            if (timeChart) timeChart.destroy();
            const timeCtx = document.getElementById('timeChart').getContext('2d');
            timeChart = new Chart(timeCtx, {
                type: 'line',
                data: {
                    labels: data.time_labels || [],
                    datasets: [{
                        label: 'Articles',
                        data: data.time_data || [],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    aspectRatio: 1.5,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
        
        function loadArticles() {
            fetch('/api/articles?limit=50')
                .then(r => r.json())
                .then(data => {
                    displayTodayArticles(data.today_articles || []);
                    displayYesterdayArticles(data.yesterday_articles || []);
                    updateFilters(data.sources || []);
                });
        }
        
        function displayTodayArticles(articles) {
            const container = document.getElementById('today-articles-container');
            if (articles.length === 0) {
                container.innerHTML = '<p>No articles found for today.</p>';
                return;
            }
            container.innerHTML = formatArticles(articles);
        }
        
        function displayYesterdayArticles(articles) {
            const container = document.getElementById('yesterday-articles-container');
            if (articles.length === 0) {
                container.innerHTML = '<p>No articles found for yesterday.</p>';
                return;
            }
            container.innerHTML = formatArticles(articles);
        }
        
        function formatArticles(articles) {
            let html = '';
            articles.forEach(article => {
                const cves = article.cve_numbers || [];
                const categories = article.categories || [];
                const summary = article.summary || '';
                const cveDetails = article.cve_details || {};
                
                const cveBadges = cves.map(cve => {
                    const nvdLink = cveDetails[cve]?.nvd_link || `https://nvd.nist.gov/vuln/detail/${cve}`;
                    return `<span class="cve-badge"><a href="${nvdLink}" target="_blank">${cve}</a></span>`;
                }).join('');
                
                const categoryTags = categories.map(cat => 
                    `<span class="category-tag">${cat}</span>`
                ).join('');
                
                let cveDetailsHtml = '';
                if (Object.keys(cveDetails).length > 0) {
                    cveDetailsHtml = '<div class="cve-details"><strong>CVE Details:</strong> ';
                    const details = Object.entries(cveDetails).map(([cve, info]) => {
                        const score = info.cvss_score ? ` (CVSS: ${info.cvss_score})` : '';
                        return `<a href="${info.nvd_link}" target="_blank">${cve}</a>${score}`;
                    }).join(', ');
                    cveDetailsHtml += details + '</div>';
                }
                
                html += `
                    <div class="article-item">
                        <div class="article-title">
                            <a href="${article.url}" target="_blank">${article.title}</a>
                        </div>
                        ${summary ? `<div class="article-summary">${summary}</div>` : ''}
                        <div>
                            ${cveBadges}
                            ${categoryTags}
                        </div>
                        ${cveDetailsHtml}
                        <div class="article-meta">
                            <strong>Source:</strong> ${article.source} | 
                            <strong>Date:</strong> ${article.date ? new Date(article.date).toLocaleDateString() : 'No date'} | 
                            <a href="${article.url}" target="_blank" class="read-more">Read Original Article →</a>
                        </div>
                    </div>
                `;
            });
            return html;
        }
        
        function updateFilters(sources) {
            const select = document.getElementById('source-filter');
            const existing = Array.from(select.options).map(o => o.value);
            sources.forEach(source => {
                if (!existing.includes(source)) {
                    const option = document.createElement('option');
                    option.value = source;
                    option.textContent = source;
                    select.appendChild(option);
                }
            });
        }
        
        function filterArticles() {
            const search = document.getElementById('search').value.toLowerCase();
            const source = document.getElementById('source-filter').value;
            const category = document.getElementById('category-filter').value;
            
            let url = '/api/articles?limit=50';
            if (search) url += `&search=${encodeURIComponent(search)}`;
            if (source) url += `&source=${encodeURIComponent(source)}`;
            if (category) url += `&category=${encodeURIComponent(category)}`;
            
            fetch(url)
                .then(r => r.json())
                .then(data => {
                    displayTodayArticles(data.today_articles || []);
                    displayYesterdayArticles(data.yesterday_articles || []);
                });
        }
        
        loadStats();
        loadArticles();
        setInterval(loadStats, 60000);
        
        // Subscribe modal functions
        function openSubscribeModal() {
            document.getElementById('subscribeModal').style.display = 'block';
            document.getElementById('subscribeEmail').focus();
        }
        
        function closeSubscribeModal() {
            document.getElementById('subscribeModal').style.display = 'none';
            document.getElementById('subscribeEmail').value = '';
            document.getElementById('subscribeSuccess').style.display = 'none';
            document.getElementById('subscribeError').style.display = 'none';
        }
        
        function subscribeEmail() {
            const email = document.getElementById('subscribeEmail').value.trim();
            const successDiv = document.getElementById('subscribeSuccess');
            const errorDiv = document.getElementById('subscribeError');
            
            // Hide previous messages
            successDiv.style.display = 'none';
            errorDiv.style.display = 'none';
            
            // Validate email
            if (!email) {
                errorDiv.textContent = 'Please enter an email address';
                errorDiv.style.display = 'block';
                return;
            }
            
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                errorDiv.textContent = 'Please enter a valid email address';
                errorDiv.style.display = 'block';
                return;
            }
            
            // Send subscription request
            fetch('/api/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    successDiv.textContent = data.message || 'Successfully subscribed! You will receive daily emails at 9:30 AM IST.';
                    successDiv.style.display = 'block';
                    document.getElementById('subscribeEmail').value = '';
                    setTimeout(() => {
                        closeSubscribeModal();
                    }, 2000);
                } else {
                    errorDiv.textContent = data.message || 'Subscription failed. Please try again.';
                    errorDiv.style.display = 'block';
                }
            })
            .catch(error => {
                errorDiv.textContent = 'An error occurred. Please try again later.';
                errorDiv.style.display = 'block';
            });
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('subscribeModal');
            if (event.target == modal) {
                closeSubscribeModal();
            }
        }
        
        // Close modal on Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeSubscribeModal();
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# Archive page HTML template
ARCHIVE_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Older News - Cyber News Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8f9fa;
            color: #212529;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 20px 40px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header-content {
            display: flex;
            align-items: center;
            gap: 40px;
            flex: 1;
        }
        .header h1 {
            font-size: 26px;
            font-weight: 700;
            margin: 0;
            letter-spacing: -0.5px;
        }
        .nav-links {
            display: flex;
            gap: 4px;
            align-items: center;
        }
        .nav-link {
            color: rgba(255, 255, 255, 0.85);
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 6px;
            transition: all 0.2s;
            font-size: 14px;
            font-weight: 500;
            background: transparent;
            border: 1px solid transparent;
        }
        .nav-link:hover {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        .nav-link.active {
            background: rgba(255, 255, 255, 0.15);
            color: white;
            border-color: rgba(255, 255, 255, 0.2);
        }
        .subscribe-btn {
            background: #ffffff;
            color: #1e3c72;
            border: none;
            padding: 10px 24px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .subscribe-btn:hover {
            background: #f8f9fa;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .filter-bar {
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .filter-bar input, .filter-bar select {
            padding: 10px;
            margin-right: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .btn {
            padding: 10px 20px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }
        .btn:hover {
            background: #2980b9;
        }
        .articles {
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .article-item {
            padding: 20px;
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }
        .article-item:hover {
            background: #f9f9f9;
        }
        .article-item:last-child {
            border-bottom: none;
        }
        .article-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .article-title a {
            color: #2c3e50;
            text-decoration: none;
        }
        .article-title a:hover {
            color: #3498db;
            text-decoration: underline;
        }
        .article-summary {
            color: #555;
            margin: 10px 0;
            line-height: 1.6;
            font-size: 14px;
        }
        .article-meta {
            font-size: 12px;
            color: #666;
            margin-top: 10px;
        }
        .cve-badge {
            display: inline-block;
            background: #e74c3c;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            margin: 5px 5px 5px 0;
            font-weight: 600;
        }
        .cve-badge a {
            color: white;
            text-decoration: none;
        }
        .category-tag {
            display: inline-block;
            background: #95a5a6;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            margin-right: 5px;
        }
        .pagination {
            margin-top: 20px;
            text-align: center;
            padding: 20px;
        }
        .pagination button {
            padding: 8px 16px;
            margin: 0 5px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .pagination button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .pagination .page-info {
            margin: 0 15px;
            color: #666;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            animation: fadeIn 0.2s;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        .modal-content {
            background-color: #ffffff;
            margin: 15% auto;
            padding: 30px;
            border-radius: 12px;
            width: 90%;
            max-width: 450px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
            animation: slideDown 0.3s;
        }
        @keyframes slideDown {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        .modal-header {
            margin-bottom: 20px;
        }
        .modal-header h2 {
            font-size: 24px;
            color: #212529;
            margin-bottom: 8px;
        }
        .modal-header p {
            font-size: 14px;
            color: #6c757d;
            margin: 0;
        }
        .modal-body {
            margin-bottom: 20px;
        }
        .modal-body input {
            width: 100%;
            padding: 12px;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            font-size: 14px;
            box-sizing: border-box;
        }
        .modal-body input:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }
        .modal-footer {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
        .modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .modal-btn-primary {
            background: #3498db;
            color: white;
        }
        .modal-btn-primary:hover {
            background: #2980b9;
        }
        .modal-btn-secondary {
            background: #95a5a6;
            color: white;
        }
        .modal-btn-secondary:hover {
            background: #7f8c8d;
        }
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 6px;
            margin-top: 10px;
            font-size: 14px;
            display: none;
        }
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 6px;
            margin-top: 10px;
            font-size: 14px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>Older News Archive</h1>
            <div class="nav-links">
                <a href="/" class="nav-link">Dashboard</a>
                <a href="/archive" class="nav-link active">Older News</a>
            </div>
        </div>
        <button class="subscribe-btn" onclick="openSubscribeModal()">Subscribe</button>
    </div>
    
    <!-- Subscribe Modal -->
    <div id="subscribeModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Subscribe to Daily Cyber News</h2>
                <p>Get the latest cybersecurity news, vulnerabilities, and exploitations delivered to your inbox daily at 9:30 AM IST</p>
            </div>
            <div class="modal-body">
                <input type="email" id="subscribeEmail" placeholder="Enter your email address" required>
                <div id="subscribeSuccess" class="success-message"></div>
                <div id="subscribeError" class="error-message"></div>
            </div>
            <div class="modal-footer">
                <button class="modal-btn modal-btn-secondary" onclick="closeSubscribeModal()">Cancel</button>
                <button class="modal-btn modal-btn-primary" onclick="subscribeEmail()">Subscribe</button>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="filter-bar">
            <input type="text" id="search" placeholder="Search articles..." onkeyup="loadArticles()">
            <select id="source-filter" onchange="loadArticles()">
                <option value="">All Sources</option>
            </select>
            <select id="category-filter" onchange="loadArticles()">
                <option value="">All Categories</option>
                <option value="vulnerability">Vulnerability</option>
                <option value="exploit">Exploit</option>
                <option value="ransomware">Ransomware</option>
                <option value="apt">APT</option>
                <option value="zero-day">Zero-Day</option>
            </select>
            <select id="date-filter" onchange="loadArticles()">
                <option value="">All Dates</option>
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
                <option value="90">Last 90 days</option>
            </select>
            <button class="btn" onclick="loadArticles()">Refresh</button>
        </div>
        
        <div class="articles" id="articles-container">
            <div class="loading">Loading articles...</div>
        </div>
        
        <div class="pagination" id="pagination" style="display: none;">
            <button onclick="changePage(-1)" id="prev-btn">Previous</button>
            <span class="page-info">Page <span id="current-page">1</span> of <span id="total-pages">1</span></span>
            <button onclick="changePage(1)" id="next-btn">Next</button>
        </div>
    </div>
    
    <script>
        let currentPage = 1;
        let totalPages = 1;
        const pageSize = 20;
        
        function loadArticles(page = 1) {
            currentPage = page;
            const search = document.getElementById('search').value;
            const source = document.getElementById('source-filter').value;
            const category = document.getElementById('category-filter').value;
            const days = document.getElementById('date-filter').value;
            
            let url = `/api/archive?page=${page}&limit=${pageSize}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;
            if (source) url += `&source=${encodeURIComponent(source)}`;
            if (category) url += `&category=${encodeURIComponent(category)}`;
            if (days) url += `&days=${days}`;
            
            document.getElementById('articles-container').innerHTML = '<div class="loading">Loading articles...</div>';
            
            fetch(url)
                .then(r => r.json())
                .then(data => {
                    displayArticles(data.articles || []);
                    updatePagination(data.total || 0, data.page || 1, data.total_pages || 1);
                    updateFilters(data.sources || []);
                })
                .catch(err => {
                    document.getElementById('articles-container').innerHTML = '<div class="loading">Error loading articles</div>';
                });
        }
        
        function displayArticles(articles) {
            const container = document.getElementById('articles-container');
            if (articles.length === 0) {
                container.innerHTML = '<div class="loading">No articles found</div>';
                return;
            }
            
            let html = '';
            articles.forEach(article => {
                const cves = article.cve_numbers || [];
                const categories = article.categories || [];
                const summary = article.summary || '';
                
                const cveBadges = cves.map(cve => 
                    `<span class="cve-badge"><a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank">${cve}</a></span>`
                ).join('');
                
                const categoryTags = categories.map(cat => 
                    `<span class="category-tag">${cat}</span>`
                ).join('');
                
                const dateStr = article.date ? new Date(article.date).toLocaleDateString() : 'No date';
                
                html += `
                    <div class="article-item">
                        <div class="article-title">
                            <a href="${article.url}" target="_blank">${article.title}</a>
                        </div>
                        ${summary ? `<div class="article-summary">${summary}</div>` : ''}
                        <div>
                            ${cveBadges}
                            ${categoryTags}
                        </div>
                        <div class="article-meta">
                            <strong>Source:</strong> ${article.source} | 
                            <strong>Date:</strong> ${dateStr} | 
                            <a href="${article.url}" target="_blank" style="color: #3498db; text-decoration: none;">Read Original Article →</a>
                        </div>
                    </div>
                `;
            });
            container.innerHTML = html;
        }
        
        function updatePagination(total, page, totalPages) {
            currentPage = page;
            totalPages = totalPages;
            
            document.getElementById('current-page').textContent = page;
            document.getElementById('total-pages').textContent = totalPages;
            document.getElementById('prev-btn').disabled = page <= 1;
            document.getElementById('next-btn').disabled = page >= totalPages;
            
            if (totalPages > 1) {
                document.getElementById('pagination').style.display = 'block';
            } else {
                document.getElementById('pagination').style.display = 'none';
            }
        }
        
        function changePage(delta) {
            const newPage = currentPage + delta;
            if (newPage >= 1 && newPage <= totalPages) {
                loadArticles(newPage);
            }
        }
        
        function updateFilters(sources) {
            const select = document.getElementById('source-filter');
            const existing = Array.from(select.options).map(o => o.value);
            sources.forEach(source => {
                if (!existing.includes(source) && source) {
                    const option = document.createElement('option');
                    option.value = source;
                    option.textContent = source;
                    select.appendChild(option);
                }
            });
        }
        
        // Load articles on page load and check for URL parameters
        function initArchive() {
            const urlParams = new URLSearchParams(window.location.search);
            const category = urlParams.get('category');
            if (category) {
                document.getElementById('category-filter').value = category;
            }
            loadArticles();
        }
        initArchive();
        
        // Subscribe modal functions (same as dashboard)
        function openSubscribeModal() {
            document.getElementById('subscribeModal').style.display = 'block';
            document.getElementById('subscribeEmail').focus();
        }
        
        function closeSubscribeModal() {
            document.getElementById('subscribeModal').style.display = 'none';
            document.getElementById('subscribeEmail').value = '';
            document.getElementById('subscribeSuccess').style.display = 'none';
            document.getElementById('subscribeError').style.display = 'none';
        }
        
        function subscribeEmail() {
            const email = document.getElementById('subscribeEmail').value.trim();
            const successDiv = document.getElementById('subscribeSuccess');
            const errorDiv = document.getElementById('subscribeError');
            
            successDiv.style.display = 'none';
            errorDiv.style.display = 'none';
            
            if (!email) {
                errorDiv.textContent = 'Please enter an email address';
                errorDiv.style.display = 'block';
                return;
            }
            
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                errorDiv.textContent = 'Please enter a valid email address';
                errorDiv.style.display = 'block';
                return;
            }
            
            fetch('/api/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    successDiv.textContent = data.message || 'Successfully subscribed! You will receive daily emails at 9:30 AM IST.';
                    successDiv.style.display = 'block';
                    document.getElementById('subscribeEmail').value = '';
                    setTimeout(() => {
                        closeSubscribeModal();
                    }, 2000);
                } else {
                    errorDiv.textContent = data.message || 'Subscription failed. Please try again.';
                    errorDiv.style.display = 'block';
                }
            })
            .catch(error => {
                errorDiv.textContent = 'An error occurred. Please try again later.';
                errorDiv.style.display = 'block';
            });
        }
        
        window.onclick = function(event) {
            const modal = document.getElementById('subscribeModal');
            if (event.target == modal) {
                closeSubscribeModal();
            }
        }
        
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeSubscribeModal();
            }
        });
    </script>
</body>
</html>
"""

@app.route('/archive')
def archive():
    return render_template_string(ARCHIVE_HTML)

@app.route('/api/subscribe', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
def subscribe():
    """Subscribe an email address to daily cyber news (GDPR compliant)."""
    try:
        # Get and sanitize input
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        data = sanitize_json_input(data)
        
        # Validate input
        is_valid, error_msg = validate_input(data, ['email'], {'email': 255})
        if not is_valid:
            return jsonify({'success': False, 'message': error_msg}), 400
        
        # Sanitize and validate email
        email = sanitize_email(data.get('email', ''))
        if not email:
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # GDPR consent (assumed given when user subscribes)
        consent_given = data.get('consent', True)
        
        # Check if email already exists
        existing = db.session.query(Recipient).filter_by(email=email).first()
        if existing:
            if existing.active:
                return jsonify({'success': False, 'message': 'This email is already subscribed'}), 400
            else:
                # Reactivate existing subscription
                existing.active = True
                try:
                    db.session.commit()
                    logger.info(f"Subscription reactivated: {email}")
                    return jsonify({'success': True, 'message': 'Subscription reactivated! You will receive daily emails at 9:30 AM IST.'})
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error reactivating subscription: {e}")
                    return jsonify({'success': False, 'message': 'An error occurred. Please try again later.'}), 500
        
        # Add new subscriber using database method (includes GDPR checks)
        recipient = db.add_recipient(email, consent_given=consent_given)
        if recipient:
            logger.info(f"New subscription: {email}")
            return jsonify({'success': True, 'message': 'Successfully subscribed! You will receive daily emails at 9:30 AM IST.'})
        else:
            return jsonify({'success': False, 'message': 'Failed to subscribe. Please check your email address.'}), 400
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error subscribing email: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again later.'}), 500

@app.route('/api/stats')
def get_stats():
    """Get statistics for last 7 days."""
    try:
        # Get date range for last 7 days
        seven_days_ago = datetime.now().date() - timedelta(days=7)
        today = datetime.now().date()
        
        # Get articles from last 7 days only
        recent_articles = db.session.query(Article).filter(
            Article.date >= seven_days_ago,
            Article.date <= today
        ).all()
        
        total = db.session.query(Article).count()
        today_articles = db.get_today_articles()
        yesterday_articles = db.get_yesterday_articles()
        
        # Get unique CVEs from last 7 days - validate CVE format strictly using utility function
        
        unique_cves = set()
        for article in recent_articles:
            if article.cve_numbers:
                cves = json.loads(article.cve_numbers)
                # Only add valid CVEs using utility function
                for cve in cves:
                    if is_valid_cve(cve):
                        unique_cves.add(cve.upper())
        
        recipients = db.session.query(Recipient).filter_by(active=True).count()
        
        # Get source distribution (last 7 days)
        sources = {}
        for article in recent_articles:
            sources[article.source] = sources.get(article.source, 0) + 1
        
        # Get category distribution (last 7 days)
        categories = {}
        for article in recent_articles:
            if article.categories:
                cats = json.loads(article.categories)
                for cat in cats:
                    categories[cat] = categories.get(cat, 0) + 1
        
        # Get top CVEs (last 7 days) - validate CVE format
        cve_counts = {}
        for article in recent_articles:
            if article.cve_numbers:
                cves = json.loads(article.cve_numbers)
                for cve in cves:
                    # Only count valid CVEs using utility function
                    if is_valid_cve(cve):
                        cve_counts[cve.upper()] = cve_counts.get(cve.upper(), 0) + 1
        
        # Sort and get top 10 CVEs
        top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get time distribution (last 7 days)
        time_data = {}
        time_labels = []
        for i in range(7):
            date = datetime.now().date() - timedelta(days=i)
            count = db.session.query(Article).filter(
                Article.date >= date,
                Article.date < date + timedelta(days=1)
            ).count()
            time_data[date.isoformat()] = count
            time_labels.append(date.strftime('%b %d'))
        
        # Prepare category heatmap data (top 20, last 7 days)
        category_heatmap = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:20]
        category_heatmap = [{'name': k, 'count': v} for k, v in category_heatmap]
        
        # Prepare CVE heatmap data (all CVEs from last 7 days, sorted by count)
        cve_heatmap = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)
        cve_heatmap = [{'name': k, 'count': v} for k, v in cve_heatmap]
        
        return jsonify({
            'total_articles': total,
            'today_articles': len(today_articles),
            'yesterday_articles': len(yesterday_articles),
            'unique_cves': len(unique_cves),
            'recipients': recipients,
            'source_labels': list(sources.keys()),
            'source_data': list(sources.values()),
            'category_labels': list(categories.keys()),
            'category_data': list(categories.values()),
            'top_cve_labels': [cve[0] for cve in top_cves],
            'top_cve_data': [cve[1] for cve in top_cves],
            'category_heatmap': category_heatmap,
            'cve_heatmap': cve_heatmap,
            'time_labels': time_labels[::-1],
            'time_data': list(time_data.values())[::-1]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/articles')
def get_articles():
    try:
        limit = int(request.args.get('limit', 50))
        search = request.args.get('search', '')
        source = request.args.get('source', '')
        category = request.args.get('category', '')
        
        # Get today's articles
        today_query = db.session.query(Article).filter(
            Article.date >= datetime.now().date()
        )
        if search:
            today_query = today_query.filter(Article.title.contains(search))
        if source:
            today_query = today_query.filter_by(source=source)
        if category:
            today_query = today_query.filter(Article.categories.contains(f'"{category}"'))
        today_articles = today_query.order_by(Article.date.desc()).limit(limit).all()
        
        # Get yesterday's articles
        yesterday = datetime.now().date() - timedelta(days=1)
        yesterday_query = db.session.query(Article).filter(
            Article.date >= yesterday,
            Article.date < datetime.now().date()
        )
        if search:
            yesterday_query = yesterday_query.filter(Article.title.contains(search))
        if source:
            yesterday_query = yesterday_query.filter_by(source=source)
        if category:
            yesterday_query = yesterday_query.filter(Article.categories.contains(f'"{category}"'))
        yesterday_articles = yesterday_query.order_by(Article.date.desc()).limit(limit).all()
        
        sources = [s[0] for s in db.session.query(Article.source).distinct().all()]
        
        return jsonify({
            'today_articles': [a.to_dict() for a in today_articles],
            'yesterday_articles': [a.to_dict() for a in yesterday_articles],
            'sources': sources
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/gdpr/export', methods=['POST'])
@rate_limit(max_requests=3, window_seconds=3600)  # 3 requests per hour
def gdpr_export():
    """GDPR data export endpoint."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        data = sanitize_json_input(data)
        email = sanitize_email(data.get('email', ''))
        
        if not email:
            return jsonify({'success': False, 'message': 'Valid email required'}), 400
        
        # Get recipient data
        recipient_data = db.get_recipient_data_export(email)
        if not recipient_data:
            return jsonify({'success': False, 'message': 'No data found for this email'}), 404
        
        # Format for GDPR export
        export_data = GDPRCompliance.format_data_export(recipient_data)
        
        logger.info(f"GDPR data export requested for: {email}")
        return jsonify({'success': True, 'data': export_data})
    except Exception as e:
        logger.error(f"Error in GDPR export: {e}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/gdpr/delete', methods=['POST'])
@rate_limit(max_requests=3, window_seconds=3600)  # 3 requests per hour
def gdpr_delete():
    """GDPR right to be forgotten endpoint."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        data = sanitize_json_input(data)
        email = sanitize_email(data.get('email', ''))
        
        if not email:
            return jsonify({'success': False, 'message': 'Valid email required'}), 400
        
        # Delete recipient data
        success = db.delete_recipient(email)
        if success:
            logger.info(f"GDPR deletion requested for: {email}")
            return jsonify({'success': True, 'message': 'Your data has been deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'No data found for this email'}), 404
    except Exception as e:
        logger.error(f"Error in GDPR deletion: {e}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/rss')
def rss_feed():
    """RSS feed endpoint."""
    category = request.args.get('category')
    source = request.args.get('source')
    limit = int(request.args.get('limit', 50))
    
    query = db.session.query(Article)
    if category:
        query = query.filter(Article.categories.contains(f'"{category}"'))
    if source:
        query = query.filter_by(source=source)
    
    articles = query.order_by(Article.date.desc()).limit(limit).all()
    
    rss_items = []
    for article in articles:
        pub_date = article.date or article.created_at
        if pub_date:
            pub_date_str = pub_date.strftime('%a, %d %b %Y %H:%M:%S +0000')
        else:
            pub_date_str = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        
        cves = json.loads(article.cve_numbers) if article.cve_numbers else []
        cve_text = ', '.join(cves) if cves else ''
        
        description = article.summary or f"Source: {article.source}"
        if cve_text:
            description += f" | CVEs: {cve_text}"
        
        item = f"""        <item>
            <title><![CDATA[{article.title}]]></title>
            <link>{article.url}</link>
            <description><![CDATA[{description}]]></description>
            <pubDate>{pub_date_str}</pubDate>
            <guid isPermaLink="true">{article.url}</guid>
        </item>"""
        rss_items.append(item)
    
    # Get port for RSS link
    web_port = os.getenv('WEB_PORT', '5000')
    rss_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>Cyber News Feed</title>
        <link>http://localhost:{web_port}/rss</link>
        <description>Daily cybersecurity news, vulnerabilities, and exploitations</description>
        <language>en-us</language>
        <lastBuildDate>{datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')}</lastBuildDate>
{chr(10).join(rss_items)}
    </channel>
</rss>"""
    
    return Response(rss_xml, mimetype='application/rss+xml')

@app.route('/api/cve/<cve_id>')
def get_cve_articles(cve_id):
    """Get articles for specific CVE."""
    try:
        articles = db.session.query(Article).filter(
            Article.cve_numbers.contains(cve_id.upper())
        ).order_by(Article.date.desc()).all()
        return jsonify({'cve': cve_id, 'articles': [a.to_dict() for a in articles]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/archive')
def get_archive_articles():
    """Get older articles with pagination."""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        search = request.args.get('search', '')
        source = request.args.get('source', '')
        category = request.args.get('category', '')
        days = request.args.get('days', '')
        
        # Calculate date cutoff (exclude today and yesterday)
        yesterday = datetime.now().date() - timedelta(days=1)
        query = db.session.query(Article).filter(Article.date < yesterday)
        
        # Apply date filter if specified
        if days:
            days_int = int(days)
            cutoff_date = datetime.now().date() - timedelta(days=days_int)
            query = query.filter(Article.date >= cutoff_date)
        
        # Apply filters
        if search:
            query = query.filter(Article.title.contains(search))
        if source:
            query = query.filter_by(source=source)
        if category:
            query = query.filter(Article.categories.contains(f'"{category}"'))
        
        # Get total count for pagination
        total = query.count()
        total_pages = (total + limit - 1) // limit  # Ceiling division
        
        # Apply pagination
        offset = (page - 1) * limit
        articles = query.order_by(Article.date.desc()).offset(offset).limit(limit).all()
        
        # Get sources for filter dropdown
        sources = [s[0] for s in db.session.query(Article.source).distinct().all()]
        
        return jsonify({
            'articles': [a.to_dict() for a in articles],
            'total': total,
            'page': page,
            'total_pages': total_pages,
            'sources': sources
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recipients', methods=['GET', 'POST'])
def manage_recipients():
    """Manage recipients."""
    if request.method == 'GET':
        recipients = db.session.query(Recipient).filter_by(active=True).all()
        return jsonify({'recipients': [r.to_dict() for r in recipients]})
    else:
        data = request.json
        email = data.get('email')
        name = data.get('name')
        if email:
            recipient = db.add_recipient(email, name)
            return jsonify({'success': True, 'recipient': recipient.to_dict()})
        return jsonify({'error': 'Email required'}), 400

def create_app():
    """Create Flask app instance."""
    return app

if __name__ == '__main__':
    # Get port from environment variable, default to 5000
    port = int(os.getenv('WEB_PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False)
