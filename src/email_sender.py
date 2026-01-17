#!/usr/bin/env python3
"""
Email Sender for Cybersecurity News
Sends daily cybersecurity news to a list of recipients via BCC.
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict
import os
from dotenv import load_dotenv
from .database import Database
from .logger import logger

# Load environment variables from config directory
env_path = os.path.join(os.path.dirname(__file__), '..', 'config', '.env')
if os.path.exists(env_path):
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class CyberNewsEmailSender:
    def __init__(self, use_db=True):
        """Initialize email sender with configuration from environment variables."""
        self.config = self.load_config()
        self.use_db = use_db
        if self.use_db:
            try:
                self.db = Database()
                logger.info("Database initialized for email sender")
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                self.use_db = False
        
    def load_config(self) -> Dict:
        """Load email configuration from environment variables."""
        config = {
            "smtp_server": os.getenv('SMTP_SERVER', 'mail.nmasnanjana.xyz'),
            "smtp_port": int(os.getenv('SMTP_PORT', '587')),
            "sender_email": os.getenv('SENDER_EMAIL', ''),
            "sender_password": os.getenv('SENDER_PASSWORD', ''),
            "subject_prefix": os.getenv('EMAIL_SUBJECT_PREFIX', 'Daily Cybersecurity News'),
            "use_tls": os.getenv('SMTP_USE_TLS', 'true').lower() == 'true',
            "use_ssl": os.getenv('SMTP_USE_SSL', 'false').lower() == 'true'
        }
        
        # Validate required fields
        if not config['sender_email']:
            raise ValueError("SENDER_EMAIL environment variable is required")
        if not config['sender_password']:
            raise ValueError("SENDER_PASSWORD environment variable is required")
        
        return config
    
    def load_news_articles(self, days=3) -> List[Dict]:
        """Load news articles from MySQL database."""
        if not self.use_db:
            logger.error("Database is required for loading articles")
            return []
        
        try:
            articles_db = self.db.get_recent_articles(days=days, limit=100)
            articles = []
            for article in articles_db:
                article_dict = article.to_dict()
                articles.append({
                    'title': article_dict['title'],
                    'url': article_dict['url'],
                    'source': article_dict['source'],
                    'date': article_dict['date'],
                    'cve_numbers': article_dict['cve_numbers'],
                    'categories': article_dict['categories']
                })
            logger.info(f"Loaded {len(articles)} articles from database")
            return articles
        except Exception as e:
            logger.error(f"Error loading from database: {e}")
            return []
    
    def format_articles_html(self, articles: List[Dict]) -> str:
        """Format articles as HTML email body."""
        if not articles:
            return """
            <html>
            <body>
                <h2>No new cybersecurity news today.</h2>
                <p>Check back tomorrow for the latest updates.</p>
            </body>
            </html>
            """
        
        today = datetime.now().strftime("%B %d, %Y")
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: Georgia, 'Times New Roman', serif;
                    line-height: 1.7;
                    color: #333;
                    background-color: #f5f5f5;
                    padding: 20px;
                    margin: 0;
                }}
                .email-wrapper {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    border: 1px solid #ddd;
                }}
                .header {{
                    background-color: #2c3e50;
                    color: white;
                    padding: 30px 40px;
                    border-bottom: 3px solid #34495e;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 24px;
                    font-weight: normal;
                    font-family: Arial, sans-serif;
                }}
                .date {{
                    font-size: 14px;
                    margin-top: 8px;
                    opacity: 0.9;
                    font-family: Arial, sans-serif;
                }}
                .content {{
                    padding: 40px;
                }}
                .intro {{
                    font-size: 14px;
                    color: #666;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eee;
                }}
                .article {{
                    margin-bottom: 35px;
                    padding-bottom: 30px;
                    border-bottom: 1px solid #eee;
                }}
                .article:last-child {{
                    border-bottom: none;
                    margin-bottom: 0;
                    padding-bottom: 0;
                }}
                .article-title {{
                    font-size: 18px;
                    font-weight: bold;
                    color: #2c3e50;
                    margin-bottom: 10px;
                    line-height: 1.4;
                }}
                .article-title a {{
                    color: #2c3e50;
                    text-decoration: none;
                }}
                .article-title a:hover {{
                    color: #3498db;
                    text-decoration: underline;
                }}
                .article-meta {{
                    font-size: 12px;
                    color: #7f8c8d;
                    margin-bottom: 8px;
                    font-family: Arial, sans-serif;
                }}
                .article-url {{
                    font-size: 12px;
                    color: #3498db;
                    word-break: break-all;
                    margin-top: 5px;
                }}
                .article-url a {{
                    color: #3498db;
                    text-decoration: none;
                }}
                .article-url a:hover {{
                    text-decoration: underline;
                }}
                .footer {{
                    background-color: #f9f9f9;
                    padding: 25px 40px;
                    border-top: 1px solid #eee;
                    text-align: center;
                }}
                .footer-text {{
                    font-size: 12px;
                    color: #7f8c8d;
                    line-height: 1.6;
                    font-family: Arial, sans-serif;
                }}
                @media only screen and (max-width: 600px) {{
                    body {{
                        padding: 10px;
                    }}
                    .content {{
                        padding: 25px !important;
                    }}
                    .header {{
                        padding: 20px 25px !important;
                    }}
                    .footer {{
                        padding: 20px 25px !important;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="email-wrapper">
                <div class="header">
                    <h1>Daily Cybersecurity News</h1>
                    <div class="date">{today}</div>
                </div>
                
                <div class="content">
                    <div class="intro">
                        {len(articles)} new article{'s' if len(articles) != 1 else ''} today
                    </div>
        """
        
        for i, article in enumerate(articles, 1):
            title = article.get('title', 'No Title')
            url = article.get('url', '#')
            source = article.get('source', 'Unknown Source')
            date = article.get('date', '')
            cve_numbers = article.get('cve_numbers', [])
            categories = article.get('categories', [])
            
            # Format date if available
            date_str = ""
            if date:
                try:
                    date_obj = datetime.fromisoformat(date.split('T')[0])
                    date_str = date_obj.strftime("%B %d, %Y")
                except:
                    date_str = date
            
            # Format CVEs
            cve_text = ""
            if cve_numbers:
                cve_links = ", ".join([f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" style="color: #3498db;">{cve}</a>' for cve in cve_numbers[:5]])
                cve_text = f'<div style="margin-top: 5px; font-size: 12px; color: #e74c3c;"><strong>CVEs:</strong> {cve_links}</div>'
            
            # Format categories
            category_text = ""
            if categories:
                category_text = f'<span style="font-size: 11px; color: #7f8c8d;"> | {", ".join(categories)}</span>'
            
            html += f"""
            <div class="article">
                <div class="article-title">
                    <a href="{url}" target="_blank">{title}</a>
                </div>
                <div class="article-meta">
                    {source}{f' • {date_str}' if date_str else ''}{category_text}
                </div>
                {cve_text}
                <div class="article-url">
                    <a href="{url}" target="_blank">{url}</a>
                </div>
            </div>
            """
        
        html += """
                </div>
                
                <div class="footer">
                    <div class="footer-text">
                        This is an automated daily cybersecurity news digest.
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def format_articles_text(self, articles: List[Dict]) -> str:
        """Format articles as plain text email body (fallback)."""
        if not articles:
            return "No new cybersecurity news today. Check back tomorrow for the latest updates."
        
        today = datetime.now().strftime("%B %d, %Y")
        
        text = f"""
{'='*80}
DAILY CYBERSECURITY NEWS - {today}
{'='*80}

{len(articles)} New Article{'s' if len(articles) != 1 else ''} Today

"""
        
        for i, article in enumerate(articles, 1):
            title = article.get('title', 'No Title')
            url = article.get('url', '#')
            source = article.get('source', 'Unknown Source')
            date = article.get('date', '')
            
            # Format date if available
            date_str = ""
            if date:
                try:
                    date_obj = datetime.fromisoformat(date.split('T')[0])
                    date_str = date_obj.strftime("%B %d, %Y")
                except:
                    date_str = date
            
            # Add CVE info if available
            cve_numbers = article.get('cve_numbers', [])
            cve_text = f"   CVEs: {', '.join(cve_numbers)}" if cve_numbers else ""
            
            text += f"""
{i}. {title}
   Source: {source}
   {f'Date: {date_str}' if date_str else ''}
   {cve_text}
   URL: {url}
   
"""
        
        text += f"""
{'='*80}
This is an automated daily cybersecurity news digest.
Stay informed, stay secure!
{'='*80}
"""
        
        return text
    
    def send_email(self, articles: List[Dict]):
        """
        Send email with news articles to all recipients via BCC.
        
        Args:
            articles: List of article dictionaries from MySQL database
        """
        if not articles:
            print("No articles to send. Email not sent.")
            return False
        
        try:
            # Get recipients from database (active subscribers)
            if not self.use_db:
                logger.error("Database is required for sending emails")
                return False
            
            recipients_list = self.db.get_active_recipients()
            recipients = [r.email for r in recipients_list]
            
            if not recipients:
                logger.warning("No active recipients found in database")
                print("Warning: No active recipients found. No email sent.")
                return False
            
            logger.info(f"Found {len(recipients)} active recipients in database")
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.config['sender_email']
            # For BCC, we send to ourselves and BCC to all recipients
            # Recipients won't see each other's email addresses
            # BCC recipients are NOT added to headers - they're only in sendmail() call
            msg['To'] = self.config['sender_email']
            msg['Subject'] = f"{self.config['subject_prefix']} - {datetime.now().strftime('%B %d, %Y')}"
            
            # Create HTML and text versions
            html_content = self.format_articles_html(articles)
            text_content = self.format_articles_text(articles)
            
            # Attach both versions
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            # Connect to SMTP server and send
            smtp_server = self.config['smtp_server']
            smtp_port = self.config['smtp_port']
            use_tls = self.config.get('use_tls', True)
            use_ssl = self.config.get('use_ssl', False)
            
            print(f"Connecting to {smtp_server}:{smtp_port}...")
            
            # Use SSL or TLS based on configuration
            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port)
                if use_tls:
                    server.starttls()
            
            # Login
            server.login(self.config['sender_email'], self.config['sender_password'])
            
            # Send email with BCC
            # BCC recipients are included in sendmail but NOT in message headers
            # This ensures privacy - recipients can't see each other
            bcc_recipients = recipients
            # Include sender in recipients list (as 'To') plus all BCC recipients
            all_recipients = [self.config['sender_email']] + bcc_recipients
            
            print(f"Sending email to {len(bcc_recipients)} recipient(s) via BCC...")
            print(f"  Recipients will receive email but won't see each other's addresses")
            server.sendmail(
                self.config['sender_email'],
                all_recipients,
                msg.as_string()
            )
            server.quit()
            
            logger.info(f"Email sent successfully to {len(bcc_recipients)} recipient(s)")
            print(f"✓ Email sent successfully to {len(bcc_recipients)} recipient(s)!")
            print(f"  Recipients (BCC): {', '.join(bcc_recipients)}")
            
            # Log to database
            if self.use_db:
                try:
                    self.db.log_email(
                        article_count=len(articles),
                        recipient_count=len(bcc_recipients),
                        success=True
                    )
                except Exception as e:
                    logger.error(f"Failed to log email to database: {e}")
            
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            error_msg = "Authentication failed. Check your email and password."
            logger.error(f"{error_msg}: {e}")
            print(f"Error: {error_msg}")
            if self.use_db:
                try:
                    self.db.log_email(0, 0, success=False, error_message=str(e))
                except:
                    pass
            return False
        except smtplib.SMTPException as e:
            logger.error(f"Error sending email: {e}")
            print(f"Error sending email: {e}")
            if self.use_db:
                try:
                    self.db.log_email(0, 0, success=False, error_message=str(e))
                except:
                    pass
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print(f"Unexpected error: {e}")
            if self.use_db:
                try:
                    self.db.log_email(0, 0, success=False, error_message=str(e))
                except:
                    pass
            return False


def main():
    """Main function to send daily cybersecurity news."""
    print("="*80)
    print("Cybersecurity News Email Sender")
    print("="*80)
    print()
    
    # Initialize sender
    sender = CyberNewsEmailSender()
    
    # Config is loaded from .env, validation happens in load_config()
    
    # Load news articles
    print("Loading news articles...")
    articles = sender.load_news_articles()
    
    if not articles:
        print("No articles found in database. Make sure to run the scraper first.")
        return
    
    print(f"Found {len(articles)} articles to send")
    print()
    
    # Send email
    success = sender.send_email(articles)
    
    if success:
        print()
        print("="*80)
        print("Email sent successfully! ✓")
        print("="*80)
    else:
        print()
        print("="*80)
        print("Failed to send email. Please check the error messages above.")
        print("="*80)


if __name__ == "__main__":
    main()
