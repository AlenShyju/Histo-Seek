from flask import Flask, render_template, request, Response, session, jsonify
import sqlite3
import os
import re
from datetime import datetime, timedelta
import tldextract
import requests
import json
import time
import socket
from cachetools import TTLCache
import logging
import glob
from pathlib import Path

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))  # Use environment variable for secret key

# VirusTotal API Key (store in environment variable for security)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "your_virustotal_api_key_here")

# Cache for VirusTotal results (1-hour TTL)
virustotal_cache = TTLCache(maxsize=100, ttl=3600)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/privacy.html')
def privacy():
    return render_template('privacy.html')

@app.route('/terms.html')
def terms():
    return render_template('terms.html')

@app.route('/guide.html')
def guide():
    return render_template('guide.html')

@app.route('/team.html')
def team():
    return render_template('team.html')

# Custom Jinja2 filter to extract domain from URL
@app.template_filter('extract_domain')
def extract_domain(url):
    """Extract domain from a URL using tldextract."""
    try:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {e}")
        return url

def is_suspicious(url):
    """Check if a URL is suspicious using keywords and regex patterns."""
    try:
        suspicious_keywords = session.get('suspicious_keywords', [
            "login", "bank", "paypal", "password", "phishing", "account", "secure", "verify", "ngrok"
        ])
        url_lower = url.lower()
        keyword_suspicious = any(keyword in url_lower for keyword in suspicious_keywords)
        
        lookalike_pattern = r"(paypa[l1]|g[o0][o0]gle|faceb[o0][o0]k|app[l1]e)"
        subdomain_pattern = r"(\w+\.){3,}\w+"
        random_string_pattern = r"[a-z0-9]{10,}\.(xyz|top|info|club|ngrok)"
        
        lookalike_suspicious = bool(re.search(lookalike_pattern, url_lower))
        subdomain_suspicious = bool(re.search(subdomain_pattern, url_lower))
        random_suspicious = bool(re.search(random_string_pattern, url_lower))
        
        is_susp = keyword_suspicious or lookalike_suspicious or subdomain_suspicious or random_suspicious
        if is_susp:
            logger.warning(f"Suspicious URL detected: {url}")
        return is_susp
    except Exception as e:
        logger.error(f"Error in is_suspicious for {url}: {e}")
        return False

def chrome_time_to_datetime(chrome_time):
    """Convert Chrome timestamp to datetime."""
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
    except Exception as e:
        logger.error(f"Error converting Chrome time {chrome_time}: {e}")
        return datetime(1970, 1, 1)

def firefox_time_to_datetime(firefox_time):
    """Convert Firefox timestamp (microseconds since epoch) to datetime."""
    try:
        return datetime.fromtimestamp(firefox_time / 1000000)
    except Exception as e:
        logger.error(f"Error converting Firefox time {firefox_time}: {e}")
        return datetime(1970, 1, 1)

def extract_ip_from_url(url):
    """Extract IP address from URL or resolve domain to IP."""
    try:
        # Try extracting IP directly from URL
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        match = re.search(ip_pattern, url)
        if match:
            return match.group(0)
        
        # Fallback: Resolve domain to IP
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        logger.warning(f"Could not resolve IP for {url}")
        return None
    except Exception as e:
        logger.error(f"Error extracting IP from {url}: {e}")
        return None

def get_geolocation(ip):
    """Get geolocation data for an IP with fallback to secondary service."""
    try:
        if not ip:
            return {"country": "N/A", "city": "N/A", "lat": None, "lon": None}
        
        # Primary service: ip-api.com
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") != "fail":
                return {
                    "country": data.get("country", "N/A"),
                    "city": data.get("city", "N/A"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon")
                }
        
        # Fallback service: ipinfo.io
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "").split(",") if data.get("loc") else [None, None]
            return {
                "country": data.get("country", "N/A"),
                "city": data.get("city", "N/A"),
                "lat": float(loc[0]) if loc[0] else None,
                "lon": float(loc[1]) if loc[1] else None
            }
        
        return {"country": "N/A", "city": "N/A", "lat": None, "lon": None}
    except requests.RequestException as e:
        logger.error(f"Network error fetching geolocation for {ip}: {e}")
        return {"country": "N/A", "city": "N/A", "lat": None, "lon": None}
    except Exception as e:
        logger.error(f"Error fetching geolocation for {ip}: {e}")
        return {"country": "N/A", "city": "N/A", "lat": None, "lon": None}

def scan_url_with_virustotal(url):
    """Scan a URL using VirusTotal API with caching and robust error handling."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            logger.error(f"Invalid URL: {url}")
            return {"error": "Invalid URL"}

        # Check cache
        if url in virustotal_cache:
            logger.info(f"Returning cached VirusTotal result for {url}")
            return virustotal_cache[url]

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        params = {"url": url}

        # Submit URL for scanning
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=params,
            timeout=15
        )

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit exceeded. Retrying after 60 seconds...")
            time.sleep(60)
            return scan_url_with_virustotal(url)
        elif response.status_code != 200:
            logger.error(f"VirusTotal API error for {url}: {response.status_code} - {response.text}")
            return {"error": f"Failed to scan URL: {response.status_code}"}

        analysis_id = response.json().get("data", {}).get("id")
        if not analysis_id:
            logger.error(f"Failed to retrieve analysis ID for {url}")
            return {"error": "Failed to retrieve analysis ID"}

        # Poll for analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for attempt in range(5):
            analysis_response = requests.get(analysis_url, headers=headers, timeout=15)
            if analysis_response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded on analysis attempt {attempt + 1}. Retrying...")
                time.sleep(60)
                continue
            elif analysis_response.status_code != 200:
                logger.error(f"VirusTotal analysis error for {url}: {analysis_response.status_code}")
                return {"error": f"Failed to retrieve analysis: {analysis_response.status_code}"}

            result = analysis_response.json().get("data", {}).get("attributes", {})
            if result.get("status") == "completed":
                stats = result.get("stats", {})
                result_data = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "last_analysis_date": result.get("last_analysis_date"),
                    "status": "completed"
                }
                virustotal_cache[url] = result_data
                logger.info(f"Successful VirusTotal scan for {url}: {result_data}")
                return result_data
            time.sleep(2)

        logger.warning(f"VirusTotal analysis timedCenters for {url}")
        return {"error": "Analysis timed out", "status": "pending"}

    except requests.RequestException as e:
        logger.error(f"Network error in VirusTotal scan for {url}: {e}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in VirusTotal scan for {url}: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

def detect_browser_type(db_path):
    """Detect if the database is from Chrome or Firefox."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        if "urls" in tables:
            return "chrome"
        elif "moz_places" in tables:
            return "firefox"
        return None
    except sqlite3.Error as e:
        logger.error(f"SQLite error detecting browser type: {e}")
        return None
    except Exception as e:
        logger.error(f"Error detecting browser type: {e}")
        return None

def extract_browser_history(history_db_path, browser_type="chrome"):
    """Extract browser history and mark as active."""
    history_data = []
    try:
        conn = sqlite3.connect(history_db_path)
        cursor = conn.cursor()
        
        if browser_type == "chrome":
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
            rows = cursor.fetchall()
            for row in rows:
                url, title, visit_count, last_visit_time = row
                last_visit_time = chrome_time_to_datetime(last_visit_time)
                ip = extract_ip_from_url(url)
                geolocation = get_geolocation(ip)
                history_data.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": last_visit_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "suspicious": is_suspicious(url),
                    "geolocation": geolocation,
                    "status": "active"
                })
        elif browser_type == "firefox":
            cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC")
            rows = cursor.fetchall()
            for row in rows:
                url, title, visit_count, last_visit_time = row
                last_visit_time = firefox_time_to_datetime(last_visit_time)
                ip = extract_ip_from_url(url)
                geolocation = get_geolocation(ip)
                history_data.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": last_visit_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "suspicious": is_suspicious(url),
                    "geolocation": geolocation,
                    "status": "active"
                })
    except sqlite3.Error as e:
        logger.error(f"SQLite error extracting history: {e}")
    except Exception as e:
        logger.error(f"Error extracting history: {e}")
    finally:
        conn.close()
    logger.info(f"Extracted {len(history_data)} active entries")
    return history_data

def recover_from_free_pages(db_path):
    """Attempt to recover URLs from SQLite free pages."""
    recovered_data = []
    try:
        with open(db_path, 'rb') as f:
            content = f.read()
            url_pattern = r"https?://[^\s<>\"]+"
            urls = re.findall(url_pattern, content.decode('utf-8', errors='ignore'))
            for url in urls:
                recovered_data.append({
                    "url": url,
                    "title": "N/A (Recovered by HISTO-SEEK)",
                    "visit_count": 1,
                    "last_visit_time": "Unknown",
                    "suspicious": is_suspicious(url),
                    "geolocation": get_geolocation(extract_ip_from_url(url)),
                    "status": "deleted (free page)"
                })
        logger.info(f"Recovered {len(recovered_data)} entries from free pages")
    except Exception as e:
        logger.error(f"Error recovering from free pages: {e}")
    return recovered_data

def recover_deleted_history(db_path, browser_type="chrome"):
    """Recover deleted browser history and mark as deleted."""
    deleted_data = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        
        if browser_type == "chrome":
            # Query hidden or null-time entries
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls WHERE hidden = 1 OR last_visit_time IS NULL")
            rows = cursor.fetchall()
            for row in rows:
                url, title, visit_count, last_visit_time = row
                if last_visit_time:
                    last_visit_time = chrome_time_to_datetime(last_visit_time)
                    ip = extract_ip_from_url(url)
                    geolocation = get_geolocation(ip)
                    deleted_data.append({
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "last_visit_time": last_visit_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "suspicious": is_suspicious(url),
                        "geolocation": geolocation,
                        "status": "deleted"
                    })
            
            # Query orphaned visits
            cursor.execute("""
                SELECT v.visit_time, v.url, u.url AS referrer
                FROM visits v
                LEFT JOIN urls u ON v.url = u.id
                WHERE u.id IS NULL
            """)
            for row in cursor.fetchall():
                visit_time, url, referrer = row
                visit_time = chrome_time_to_datetime(visit_time)
                ip = extract_ip_from_url(url)
                geolocation = get_geolocation(ip)
                deleted_data.append({
                    "url": url,
                    "title": "N/A (Orphaned Visit)",
                    "visit_count": 1,
                    "last_visit_time": visit_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "suspicious": is_suspicious(url),
                    "geolocation": geolocation,
                    "status": "deleted"
                })

        elif browser_type == "firefox":
            # Query hidden entries
            cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE hidden = 1")
            rows = cursor.fetchall()
            for row in rows:
                url, title, visit_count, last_visit_time = row
                last_visit_time = firefox_time_to_datetime(last_visit_time)
                ip = extract_ip_from_url(url)
                geolocation = get_geolocation(ip)
                deleted_data.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": last_visit_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "suspicious": is_suspicious(url),
                    "geolocation": geolocation,
                    "status": "deleted"
                })
            
            # Query orphaned visits
            cursor.execute("""
                SELECT v.visit_date, p.url, h.url AS referrer
                FROM moz_historyvisits v
                LEFT JOIN moz_places p ON v.place_id = p.id
                LEFT JOIN moz_places h ON v.from_visit = h.id
                WHERE p.hidden = 1 OR p.id IS NULL
            """)
            for row in cursor.fetchall():
                visit_time, url, referrer = row
                visit_time = firefox_time_to_datetime(visit_time)
                ip = extract_ip_from_url(url)
                geolocation = get_geolocation(ip)
                deleted_data.append({
                    "url": url,
                    "title": "N/A (Orphaned Visit)",
                    "visit_count": 1,
                    "last_visit_time": visit_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "suspicious": is_suspicious(url),
                    "geolocation": geolocation,
                    "status": "deleted"
                })
        
        conn.close()
        
        # Recover from free pages
        deleted_data.extend(recover_from_free_pages(db_path))
    
    except sqlite3.Error as e:
        logger.error(f"SQLite error recovering deleted history: {e}")
    except Exception as e:
        logger.error(f"Error recovering deleted history: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
    logger.info(f"Recovered {len(deleted_data)} deleted entries")
    return deleted_data

def extract_cache_data(cache_dir):
    """Extract potential URLs from browser cache files."""
    cache_data = []
    try:
        if not os.path.exists(cache_dir):
            logger.warning(f"Cache directory {cache_dir} does not exist")
            return cache_data
        
        cache_files = glob.glob(os.path.join(cache_dir, "*"))
        url_pattern = r"https?://[^\s<>\"]+"
        for file_path in cache_files:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(1024)  # Read first 1024 bytes to avoid large files
                    urls = re.findall(url_pattern, content.decode('utf-8', errors='ignore'))
                    for url in urls:
                        cache_data.append({
                            "url": url,
                            "title": "N/A (Cache)",
                            "visit_count": 1,
                            "last_visit_time": "Unknown",
                            "suspicious": is_suspicious(url),
                            "geolocation": get_geolocation(extract_ip_from_url(url)),
                            "status": "incognito (cache)"
                        })
            except Exception as e:
                logger.error(f"Error reading cache file {file_path}: {e}")
        logger.info(f"Extracted {len(cache_data)} URLs from cache")
    except Exception as e:
        logger.error(f"Error extracting cache data: {e}")
    return cache_data

def sanitize_path(path):
    """Sanitize file path to prevent directory traversal."""
    try:
        base_path = Path(path).resolve()
        uploads_path = Path("uploads").resolve()
        if not base_path.is_dir() or not str(base_path).startswith(str(uploads_path)):
            raise ValueError("Invalid cache directory path")
        return str(base_path)
    except Exception as e:
        logger.error(f"Error sanitizing path {path}: {e}")
        return None

def extract_session_data(history_db_path, browser_type="chrome"):
    """Extract session data with referrers."""
    session_data = []
    try:
        conn = sqlite3.connect(history_db_path)
        cursor = conn.cursor()
        
        if browser_type == "chrome":
            cursor.execute("""
                SELECT v.visit_time, u.url, u2.url AS referrer
                FROM visits v
                JOIN urls u ON v.url = u.id
                LEFT JOIN visits v2 ON v.from_visit = v2.id
                LEFT JOIN urls u2 ON v2.url = u2.id
            """)
            rows = cursor.fetchall()
            for row in rows:
                visit_time, url, referrer = row
                visit_time = chrome_time_to_datetime(visit_time).strftime("%Y-%m-%d %H:%M:%S")
                session_data.append({
                    "url": url,
                    "referrer": referrer or "Direct",
                    "visit_time": visit_time
                })
        elif browser_type == "firefox":
            cursor.execute("""
                SELECT p.last_visit_date, p.url, h.url AS referrer
                FROM moz_places p
                LEFT JOIN moz_historyvisits v ON p.id = v.place_id
                LEFT JOIN moz_places h ON v.from_visit = h.id
            """)
            rows = cursor.fetchall()
            for row in rows:
                visit_time, url, referrer = row
                last_visit_time = firefox_time_to_datetime(visit_time)
                session_data.append({
                    "url": url,
                    "referrer": referrer or "Direct",
                    "visit_time": last_visit_time.strftime("%Y-%m-%d %H:%M:%S")
                })
    except sqlite3.Error as e:
        logger.error(f"SQLite error extracting session data: {e}")
    except Exception as e:
        logger.error(f"Error extracting session data: {e}")
    finally:
        conn.close()
    return session_data

def extract_downloads(history_db_path, browser_type="chrome"):
    """Extract download history."""
    downloads = []
    try:
        conn = sqlite3.connect(history_db_path)
        cursor = conn.cursor()
        
        if browser_type == "chrome":
            cursor.execute("SELECT target_path, start_time, received_bytes, referrer FROM downloads")
            rows = cursor.fetchall()
            for row in rows:
                path, start_time, size, referrer = row
                start_time = chrome_time_to_datetime(start_time).strftime("%Y-%m-%d %H:%M:%S")
                downloads.append({
                    "file_path": path,
                    "download_time": start_time,
                    "size_bytes": size,
                    "referrer": referrer or "N/A"
                })
    except sqlite3.Error as e:
        logger.error(f"SQLite error extracting downloads: {e}")
    except Exception as e:
        logger.error(f"Error extracting downloads: {e}")
    finally:
        conn.close()
    return downloads

@app.route("/", methods=["GET", "POST"])
def index():
    """Handle the main page with file upload and keyword management."""
    try:
        if 'suspicious_keywords' not in session:
            session['suspicious_keywords'] = [
                "login", "bank", "paypal", "password", "phishing", "account", "secure", "verify", "ngrok"
            ]
        
        if request.method == "POST":
            if "history_db" in request.files:
                file = request.files["history_db"]
                if file.filename == "":
                    return "No file selected", 400
                
                file_path = os.path.join("uploads", file.filename)
                file.save(file_path)
                
                browser_type = detect_browser_type(file_path)
                if not browser_type:
                    os.remove(file_path)
                    return "Unsupported browser database", 400
                
                history_data = extract_browser_history(file_path, browser_type)
                deleted_data = recover_deleted_history(file_path, browser_type)
                session_data = extract_session_data(file_path, browser_type)
                downloads = extract_downloads(file_path, browser_type) if browser_type == "chrome" else []
                
                # Check for cache directory (optional)
                cache_data = []
                cache_dir = request.form.get("cache_dir", "").strip()
                if cache_dir:
                    cache_dir = sanitize_path(cache_dir)
                    if cache_dir:
                        cache_data = extract_cache_data(cache_dir)
                
                combined_data = history_data + deleted_data + cache_data
                for entry in combined_data:
                    logger.debug(f"URL: {entry['url']}, Status: {entry['status']}")
                
                session['history_data'] = combined_data
                session['session_data'] = session_data
                session['downloads'] = downloads
                
                os.remove(file_path)
            
            elif "add_keyword" in request.form:
                new_keyword = request.form.get("new_keyword", "").strip().lower()
                if new_keyword and new_keyword not in session['suspicious_keywords']:
                    session['suspicious_keywords'].append(new_keyword)
                    session.modified = True
                    if 'history_data' in session:
                        for entry in session['history_data']:
                            entry['suspicious'] = is_suspicious(entry['url'])
            
            elif "remove_keyword" in request.form:
                keyword_to_remove = request.form.get("keyword_to_remove", "").strip().lower()
                if keyword_to_remove in session['suspicious_keywords']:
                    session['suspicious_keywords'].remove(keyword_to_remove)
                    session.modified = True
                    if 'history_data' in session:
                        for entry in session['history_data']:
                            entry['suspicious'] = is_suspicious(entry['url'])
            
            return render_template("index.html", 
                                 history_data=session.get('history_data', []),
                                 session_data=session.get('session_data', []),
                                 downloads=session.get('downloads', []),
                                 suspicious_keywords=session['suspicious_keywords'])
        
        return render_template("index.html", 
                             history_data=session.get('history_data', []),
                             session_data=session.get('session_data', []),
                             downloads=session.get('downloads', []),
                             suspicious_keywords=session['suspicious_keywords'])
    
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return "An error occurred while processing your request", 500

@app.route("/scan_url", methods=["POST"])
def scan_url():
    """Scan an individual URL with VirusTotal and geolocation."""
    url = request.form.get("scan_url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    virustotal_result = scan_url_with_virustotal(url)
    is_susp = is_suspicious(url)
    ip = extract_ip_from_url(url)
    geo = get_geolocation(ip)
    
    # Determine threat level
    threat_level = "Low"
    if is_susp or virustotal_result.get("malicious", 0) > 0 or virustotal_result.get("suspicious", 0) > 0:
        threat_level = "High" if virustotal_result.get("malicious", 0) > 0 else "Medium"
    
    result = {
        "url": url,
        "virustotal": virustotal_result,
        "suspicious": is_susp,
        "geolocation": geo,
        "ip": ip,
        "threat_level": threat_level
    }
    session['last_scan'] = result
    logger.info(f"Scan result for {url}: {result}")
    return jsonify(result)

@app.route("/download_scan", methods=["GET"])
def download_scan():
    """Download the last URL scan result as JSON."""
    try:
        last_scan = session.get('last_scan', {})
        if not last_scan:
            return "No scan data available", 400
        
        def generate():
            yield json.dumps(last_scan, indent=2)
        
        response = Response(generate(), mimetype="application/json")
        response.headers["Content-Disposition"] = "attachment; filename=scan_result.json"
        return response
    
    except Exception as e:
        logger.error(f"Error in download_scan route: {e}")
        return "Error generating scan result", 500

@app.route("/download", methods=["GET"])
def download():
    """Download browser history as CSV."""
    try:
        history_data = session.get('history_data', [])
        for entry in history_data:
            entry['suspicious'] = is_suspicious(entry['url'])
        
        def generate():
            yield "URL,Title,Visit Count,Last Visit Time,Suspicious,Geolocation,Status\n"
            for entry in history_data:
                geo = f"{entry['geolocation']['country']}, {entry['geolocation']['city']}" if entry['geolocation'] else 'N/A'
                suspicious = 'Yes' if entry.get('suspicious') else 'No'
                yield f"\"{entry['url']}\",\"{entry['title']}\",{entry['visit_count']},\"{entry['last_visit_time']}\",{suspicious},\"{geo}\",\"{entry['status']}\"\n"
        
        response = Response(generate(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=browser_history_analysis.csv"
        return response
    
    except Exception as e:
        logger.error(f"Error in download route: {e}")
        return "Error generating CSV", 500

# if __name__ == "__main__":      // For local run
#     try:
#         if not os.path.exists("uploads"):
#             os.makedirs("uploads")
#         app.run(debug=True)
#     except Exception as e:
#         logger.error(f"Error starting app: {e}")

if __name__ == "__main__":    // ONLY FOR RENDER SERVICE
    try:
        if not os.path.exists("uploads"):
            os.makedirs("uploads")
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port, debug=True)
    except Exception as e:
        logger.error(f"Error starting app: {e}")
