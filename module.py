import os
import json
import threading
import time
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Default settings
default_settings = {
    'scanner': {
        'concurrent_threads': 5,
        'payloads': ["' OR '1'='1", "' OR '1'='1' -- ", "' OR '1'='1' /*"],  # Example payloads; customize as needed
        'sql_errors': [
            'you have an error in your sql syntax;',
            'warning: mysql',
            'unclosed quotation mark after the character string',
            'quoted string not properly terminated',
            'sql syntax error',
            'supplied argument is not a valid MySQL result resource',
            # Add more SQL error signatures as needed
        ],
        'request_timeout': 10  # Timeout for HTTP requests in seconds
    },
    'traffic_checker': {
        'request_delay': 1,        # Seconds before every request
        'max_retries': 3,          # Maximum number of retries for 403 responses
        'min_visitors': 1000       # Minimum monthly visitor target
    },
    'vuln_anti_public': False      # Feature to prevent scanning URLs from already scanned domains
}

# Cumulative data (Lifetime)
totals_file = 'totals.json'
cumulative_data = {
    'total_urls_scanned': 0,
    'total_vulnerabilities_found': 0
}

# Domains scanned to prevent re-scanning
domains_file = 'Domains.txt'
if not os.path.exists(domains_file):
    with open(domains_file, 'w') as df:
        pass  # Create the file if it doesn't exist

# Lock for thread-safe operations
lock = threading.Lock()

def load_settings():
    global default_settings
    if os.path.exists('settings.json'):
        with open('settings.json', 'r', encoding='utf-8') as f:
            try:
                loaded_settings = json.load(f)
                # Merge loaded settings with default settings to ensure all keys are present
                for key in default_settings:
                    if key not in loaded_settings:
                        loaded_settings[key] = default_settings[key]
                    else:
                        if isinstance(default_settings[key], dict) and isinstance(loaded_settings[key], dict):
                            for sub_key in default_settings[key]:
                                if sub_key not in loaded_settings[key]:
                                    loaded_settings[key][sub_key] = default_settings[key][sub_key]
                default_settings = loaded_settings
                logging.info("Settings loaded successfully.")
            except json.JSONDecodeError:
                logging.error("Error decoding settings.json. Using default settings.")
    else:
        save_settings()  # Save default settings if settings.json does not exist
        logging.info("settings.json not found. Created with default settings.")

def save_settings():
    with open('settings.json', 'w', encoding='utf-8') as f:
        json.dump(default_settings, f, indent=4)
    logging.info("Settings saved successfully.")

def load_cumulative_data():
    global cumulative_data
    if os.path.exists(totals_file):
        with open(totals_file, 'r', encoding='utf-8') as f:
            try:
                loaded_data = json.load(f)
                # Merge loaded data with cumulative_data to ensure all keys are present
                for key in cumulative_data:
                    if key not in loaded_data:
                        loaded_data[key] = cumulative_data[key]
                cumulative_data = loaded_data
                logging.info("Cumulative data loaded successfully.")
            except json.JSONDecodeError:
                logging.error("Error decoding totals.json. Using default cumulative data.")
    else:
        save_cumulative_data()  # Save default cumulative data if totals.json does not exist
        logging.info("totals.json not found. Created with default cumulative data.")

def save_cumulative_data():
    with open(totals_file, 'w', encoding='utf-8') as f:
        json.dump(cumulative_data, f, indent=4)
    logging.info("Cumulative data saved successfully.")

def load_scanned_domains():
    """Load scanned domains from Domains.txt."""
    with open(domains_file, 'r', encoding='utf-8') as df:
        domains = set(line.strip().lower() for line in df if line.strip())
    return domains

def add_scanned_domain(domain):
    """Add a domain to Domains.txt."""
    with open(domains_file, 'a', encoding='utf-8') as df:
        df.write(domain.lower() + '\n')
    logging.info(f"Domain added to Domains.txt: {domain}")

# Initialize settings and data
load_settings()
load_cumulative_data()

# Global variables for Scanner
scanner_total_urls_scanned = 0
scanner_total_vulnerabilities_found = 0
scanner_scan_results = []  # List of dictionaries: [{'url': '...', 'vulnerable': True/False}, ...]
scanner_spm_data = []       # List to store SPM values
scanner_start_time = None
scanner_scanning = False
scanner_stop_requested = False

# Global variables for Traffic Checker
traffic_scanning = False
traffic_stop_requested = False
traffic_counters = {
    'total_urls_scanned': 0,
    'urls_over_min_visitors': 0
}
traffic_results = []  # List of URLs that meet the visitor target

# Allowed file extensions
def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def scanner():
    """Handle the Scanner page."""
    global scanner_scanning, scanner_total_urls_scanned, scanner_total_vulnerabilities_found, scanner_scan_results, scanner_spm_data, scanner_start_time, scanner_stop_requested
    if request.method == 'POST':
        # Handle file upload
        if 'url_file' not in request.files:
            flash('No file part in the request.', 'danger')
            logging.warning("No file part in the request.")
            return redirect(request.url)
        file = request.files['url_file']
        if file.filename == '':
            flash('No file selected for uploading.', 'danger')
            logging.warning("No file selected for uploading.")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            # Read URLs from the file with utf-8 encoding
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
            except UnicodeDecodeError:
                flash('File encoding not supported. Please upload a UTF-8 encoded file.', 'danger')
                logging.error("UnicodeDecodeError: File encoding not supported.")
                return redirect(request.url)
            if not urls:
                flash('The uploaded file is empty.', 'danger')
                logging.warning("Uploaded file is empty.")
                return redirect(request.url)
            
            # Get scanner settings
            concurrent_threads = default_settings['scanner']['concurrent_threads']
            
            # Vuln Anti Public Feature: Filter URLs if enabled
            if default_settings.get('vuln_anti_public', False):
                scanned_domains = load_scanned_domains()
                original_count = len(urls)
                urls = [url for url in urls if urlparse(url).netloc.lower() not in scanned_domains]
                filtered_count = original_count - len(urls)
                logging.info(f"Vuln Anti Public enabled: Filtered out {filtered_count} URLs based on Domains.txt")
                if not urls:
                    flash('All URLs have already been scanned.', 'warning')
                    logging.info("All URLs have already been scanned. No URLs to scan.")
                    return redirect(request.url)
            
            # Reset current scan counters and results
            with lock:
                scanner_total_urls_scanned = 0
                scanner_total_vulnerabilities_found = 0
                scanner_scan_results = []
                scanner_spm_data = []
                scanner_scanning = True
                scanner_stop_requested = False
                scanner_start_time = time.time()  # Record the scan start time
            
            # Start scanning in a separate thread
            threading.Thread(target=start_scan, args=(urls, concurrent_threads)).start()
            flash('Scan started successfully!', 'success')
            logging.info("Scan started successfully.")
            return redirect(url_for('scanner'))
        else:
            flash('Allowed file types are TXT.', 'danger')
            logging.warning("Attempted to upload a file with disallowed extension.")
            return redirect(request.url)
    return render_template('index.html', scanning=scanner_scanning)

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    """Handle the stop scan request."""
    global scanner_stop_requested
    scanner_stop_requested = True
    logging.info("Stop scan requested by user.")
    return jsonify({"status": "stopping_scan"})

@app.route('/reset_scan', methods=['POST'])
def reset_scan():
    """Handle the reset scan request."""
    global scanner_total_urls_scanned, scanner_total_vulnerabilities_found, scanner_scan_results, scanner_spm_data, scanner_start_time, scanner_scanning, scanner_stop_requested
    with lock:
        scanner_total_urls_scanned = 0
        scanner_total_vulnerabilities_found = 0
        scanner_scan_results = []
        scanner_spm_data = []
        scanner_start_time = None
        scanner_scanning = False
        scanner_stop_requested = False
    logging.info("Scan reset by user.")
    return jsonify({"status": "reset_scan"})

def start_scan(urls, concurrent_threads):
    """Start scanning the list of URLs."""
    global scanner_scanning
    logging.info(f"Starting scan with {concurrent_threads} concurrent threads.")
    with ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
        futures = []
        for url in urls:
            if scanner_stop_requested:
                logging.info("Scan stop requested. Terminating scan.")
                break
            futures.append(executor.submit(scan_url, url))
        # Wait for all futures to complete or stop
        for future in futures:
            if scanner_stop_requested:
                break
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error during scanning: {e}")
    with lock:
        scanner_scanning = False
        # Update cumulative data
        cumulative_data['total_urls_scanned'] += scanner_total_urls_scanned
        cumulative_data['total_vulnerabilities_found'] += scanner_total_vulnerabilities_found
        save_cumulative_data()
    logging.info("Scan completed.")
    flash('Scan completed.', 'success')

def scan_url(url):
    """Scan a single URL for SQL vulnerabilities by injecting payloads into URL parameters."""
    global scanner_total_urls_scanned, scanner_total_vulnerabilities_found, scanner_scan_results, cumulative_data
    url = url.strip()
    if not url or scanner_stop_requested:
        return
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if not query_params:
        # If there are no query parameters, skip scanning
        with lock:
            scanner_total_urls_scanned += 1
        scanner_scan_results.append({'url': url, 'vulnerable': False})
        logging.info(f"Skipped URL (no parameters): {url}")
        return
    vulnerable = False
    for param in query_params:
        original_values = query_params[param]
        for payload in default_settings['scanner']['payloads']:
            # Inject payload into the parameter
            injected_values = [value + payload for value in original_values]
            new_query = {k: v for k, v in query_params.items()}
            new_query[param] = injected_values
            # Reconstruct the URL with the injected payload
            new_query_string = urlencode(new_query, doseq=True)
            injected_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query_string,
                parsed_url.fragment
            ))
            try:
                logging.info(f"Scanning URL: {injected_url}")
                response = requests.get(injected_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=default_settings['scanner']['request_timeout'])
                content = response.text.lower()
                for error in default_settings['scanner']['sql_errors']:
                    if error.lower() in content:
                        vulnerable = True
                        with lock:
                            scanner_total_vulnerabilities_found += 1
                            scanner_total_urls_scanned += 1
                            scanner_scan_results.append({'url': url, 'vulnerable': True})
                        logging.warning(f"Vulnerability found at URL: {url}")
                        break
                if vulnerable:
                    break
            except requests.RequestException as e:
                logging.error(f"Error scanning URL {injected_url}: {e}")
        if vulnerable:
            break
    if not vulnerable:
        with lock:
            scanner_total_urls_scanned += 1
            scanner_scan_results.append({'url': url, 'vulnerable': False})
        logging.info(f"No vulnerability detected for URL: {url}")
    
    # Add domain to Domains.txt if Vuln Anti Public is enabled
    if default_settings.get('vuln_anti_public', False):
        domain = parsed_url.netloc.lower()
        add_scanned_domain(domain)

@app.route('/status')
def status():
    """Provide real-time status updates for the scanner."""
    spm = calculate_spm()
    return jsonify({
        'total_urls_scanned': scanner_total_urls_scanned,
        'total_vulnerabilities_found': scanner_total_vulnerabilities_found,
        'scanning': scanner_scanning,
        'spm': spm,
        'spm_data': scanner_spm_data
    })

def calculate_spm():
    """Calculate the average Scans Per Minute (SPM)."""
    global scanner_start_time, scanner_total_urls_scanned, scanner_spm_data
    if scanner_start_time is None:
        return 0
    elapsed_minutes = (time.time() - scanner_start_time) / 60
    if elapsed_minutes > 0:
        spm = scanner_total_urls_scanned / elapsed_minutes
        spm = round(spm, 2)
        with lock:
            scanner_spm_data.append(spm)
        return spm
    return 0

@app.route('/dashboard')
def dashboard():
    """Render the dashboard with cumulative statistics."""
    return render_template('dashboard.html',
                           total_urls_scanned=cumulative_data['total_urls_scanned'],
                           total_vulnerabilities_found=cumulative_data['total_vulnerabilities_found'],
                           spm=calculate_spm())

@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    """Handle the Settings page."""
    if request.method == 'POST':
        try:
            # Update Scanner Settings
            concurrent_threads = int(request.form.get('concurrent_threads', default_settings['scanner']['concurrent_threads']))
            payloads = request.form.get('payloads', '').strip().split('\n')
            payloads = [payload.strip() for payload in payloads if payload.strip()]
            sql_errors = request.form.get('sql_errors', '').strip().split('\n')
            sql_errors = [error.strip() for error in sql_errors if error.strip()]
            request_timeout = int(request.form.get('request_timeout', default_settings['scanner']['request_timeout']))
            
            # Update Traffic Checker Settings
            request_delay = float(request.form.get('request_delay', default_settings['traffic_checker']['request_delay']))
            max_retries = int(request.form.get('max_retries', default_settings['traffic_checker']['max_retries']))
            min_visitors = int(request.form.get('min_visitors', default_settings['traffic_checker']['min_visitors']))
            
            # Update Vuln Anti Public Setting
            vuln_anti_public = bool(request.form.get('vuln_anti_public', False))
            
            # Save to settings
            with lock:
                default_settings['scanner']['concurrent_threads'] = concurrent_threads
                default_settings['scanner']['payloads'] = payloads
                default_settings['scanner']['sql_errors'] = sql_errors
                default_settings['scanner']['request_timeout'] = request_timeout
                default_settings['traffic_checker']['request_delay'] = request_delay
                default_settings['traffic_checker']['max_retries'] = max_retries
                default_settings['traffic_checker']['min_visitors'] = min_visitors
                default_settings['vuln_anti_public'] = vuln_anti_public
            save_settings()
            flash('Settings updated successfully!', 'success')
            logging.info("Settings updated by user.")
            return redirect(url_for('settings_page'))
        except ValueError as e:
            flash('Invalid input. Please ensure all fields are correctly filled.', 'danger')
            logging.error(f"Error updating settings: {e}")
            return redirect(url_for('settings_page'))
    return render_template('settings.html', settings=default_settings)

@app.route('/traffic_checker', methods=['GET', 'POST'])
def traffic_checker():
    """Handle the Traffic Checker page."""
    global traffic_scanning, traffic_stop_requested, traffic_counters, traffic_results
    if request.method == 'POST':
        # Handle file upload
        if 'url_file' not in request.files:
            flash('No file part in the request.', 'danger')
            logging.warning("No file part in the traffic checker request.")
            return jsonify({'status': 'error', 'message': 'No file part in the request.'}), 400
        file = request.files['url_file']
        if file.filename == '':
            flash('No file selected for uploading.', 'danger')
            logging.warning("No file selected for uploading in traffic checker.")
            return jsonify({'status': 'error', 'message': 'No file selected for uploading.'}), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            # Read URLs from the file with utf-8 encoding
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
            except UnicodeDecodeError:
                flash('File encoding not supported. Please upload a UTF-8 encoded file.', 'danger')
                logging.error("UnicodeDecodeError: Traffic checker file encoding not supported.")
                return jsonify({'status': 'error', 'message': 'File encoding not supported. Please upload a UTF-8 encoded file.'}), 400
            if not urls:
                flash('The uploaded file is empty.', 'danger')
                logging.warning("Uploaded traffic checker file is empty.")
                return jsonify({'status': 'error', 'message': 'The uploaded file is empty.'}), 400
            
            # Get traffic checker settings
            request_delay = default_settings['traffic_checker']['request_delay']
            max_retries = default_settings['traffic_checker']['max_retries']
            min_visitors = default_settings['traffic_checker']['min_visitors']
            
            # Reset traffic counters and results
            with lock:
                traffic_counters = {
                    'total_urls_scanned': 0,
                    'urls_over_min_visitors': 0
                }
                traffic_results = []
                traffic_scanning = True
                traffic_stop_requested = False
            
            # Start traffic checking in a separate thread
            threading.Thread(target=start_traffic_check, args=(urls, request_delay, max_retries, min_visitors)).start()
            flash('Traffic check started successfully!', 'success')
            logging.info("Traffic check started by user.")
            return jsonify({'status': 'success', 'message': 'Traffic check started successfully!'}), 200
        else:
            flash('Allowed file types are TXT.', 'danger')
            logging.warning("Attempted to upload a traffic checker file with disallowed extension.")
            return jsonify({'status': 'error', 'message': 'Allowed file types are TXT.'}), 400
    return render_template('traffic_checker.html', scanning_traffic=traffic_scanning)

@app.route('/stop_traffic', methods=['POST'])
def stop_traffic():
    """Handle the stop traffic check request."""
    global traffic_stop_requested
    traffic_stop_requested = True
    logging.info("Stop traffic check requested by user.")
    return jsonify({"status": "stopping_traffic_check"})

@app.route('/reset_traffic', methods=['POST'])
def reset_traffic():
    """Handle the reset traffic check request."""
    global traffic_counters, traffic_results, traffic_scanning, traffic_stop_requested
    with lock:
        traffic_counters = {
            'total_urls_scanned': 0,
            'urls_over_min_visitors': 0
        }
        traffic_results = []
        traffic_scanning = False
        traffic_stop_requested = False
    logging.info("Traffic check reset by user.")
    return jsonify({"status": "reset_traffic_check"})

def start_traffic_check(urls, request_delay, max_retries, min_visitors):
    """Start checking traffic for the list of URLs."""
    global traffic_scanning
    logging.info(f"Starting traffic check with delay {request_delay}s, max retries {max_retries}, min visitors {min_visitors}.")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for url in urls:
            if traffic_stop_requested:
                logging.info("Traffic check stop requested. Terminating traffic check.")
                break
            futures.append(executor.submit(check_traffic, url, request_delay, max_retries, min_visitors))
        # Wait for all futures to complete or stop
        for future in futures:
            if traffic_stop_requested:
                break
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error during traffic check: {e}")
    with lock:
        traffic_scanning = False
        # Update cumulative data
        cumulative_data['total_traffic_checks'] += traffic_counters['total_urls_scanned']
        cumulative_data['total_urls_over_target'] += traffic_counters['urls_over_min_visitors']
        save_cumulative_data()
    logging.info("Traffic check completed.")
    flash('Traffic check completed.', 'success')

def check_traffic(url, delay, max_retries, min_visitors):
    """Check traffic for a single URL's domain."""
    global traffic_counters, traffic_results
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    retries = 0
    while retries <= max_retries:
        visits = get_estimated_visits_sync(domain)
        if visits == '403':
            retries += 1
            logging.warning(f"403 Forbidden for domain {domain}. Retry {retries}/{max_retries}.")
            time.sleep(delay)
            continue
        elif visits is not None:
            if visits >= min_visitors:
                with lock:
                    traffic_counters['urls_over_min_visitors'] += 1
                    traffic_results.append(url)  # Store full URL
                logging.info(f"URL meets visitor target: {url} with {visits} visits.")
            else:
                logging.info(f"URL does not meet visitor target: {url} with {visits} visits.")
            break
        else:
            logging.error(f"Failed to retrieve traffic data for domain {domain}.")
            break
    with lock:
        traffic_counters['total_urls_scanned'] += 1
    time.sleep(delay)

def get_estimated_visits_sync(domain):
    """Fetch estimated monthly visits for a domain using SimilarWeb API."""
    url = f"https://data.similarweb.com/api/v1/data?domain={domain}"

    headers = {
        "accept": "application/json",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6",
        "cache-control": "max-age=0",
        "sec-ch-ua": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
    }

    try:
        logging.info(f"Fetching traffic data for domain: {domain}")
        response = requests.get(url, headers=headers, timeout=default_settings['scanner']['request_timeout'])
        if response.status_code == 200:
            data = response.json()
            visits_data = data.get('EstimatedMonthlyVisits', {})
            total_visits = sum(visits_data.values())
            logging.info(f"Domain {domain} has {total_visits} estimated monthly visits.")
            return total_visits
        elif response.status_code == 403:
            # Handle 403 Forbidden by returning a special flag
            logging.warning(f"403 Forbidden for domain {domain}.")
            return '403'  # Indicate a retry is needed
        else:
            # Handle other non-200 responses by returning None
            logging.error(f"Non-200 response for domain {domain}: {response.status_code}")
            return None  # Indicate failure
    except Exception as e:
        # Handle exceptions by logging and returning None
        logging.error(f"Exception while fetching traffic data for domain {domain}: {e}")
        return None  # Indicate failure

@app.route('/traffic_status')
def traffic_status():
    """Provide real-time status updates for the traffic checker."""
    return jsonify({
        'total_urls_scanned': traffic_counters['total_urls_scanned'],
        'urls_over_min_visitors': traffic_counters['urls_over_min_visitors'],
        'scanning_traffic': traffic_scanning
    })

@app.route('/download_vulnerable_urls', methods=['GET'])
def download_vulnerable_urls():
    """Allow users to download the list of vulnerable URLs from the scanner."""
    if not scanner_scan_results:
        flash("No scan has been performed yet.", "info")
        logging.info("Download attempted without any scan results.")
        return redirect(url_for('scanner'))
    vulnerable = [result['url'] for result in scanner_scan_results if result['vulnerable']]
    if not vulnerable:
        flash("No vulnerable URLs found during this scan.", "info")
        logging.info("Download attempted but no vulnerable URLs found.")
        return redirect(url_for('scanner'))
    output = BytesIO()
    output.write(("\n".join(vulnerable)).encode('utf-8'))
    output.seek(0)
    logging.info("Vulnerable URLs downloaded by user.")
    return send_file(output, as_attachment=True, download_name="vulnerable_urls.txt", mimetype="text/plain")

@app.route('/download_traffic_results', methods=['GET'])
def download_traffic_results():
    """Allow users to download the list of URLs that meet the visitor target."""
    if not traffic_results:
        flash("No URLs meet the minimum visitor target.", "info")
        logging.info("Download attempted without any traffic results.")
        return redirect(url_for('traffic_checker'))
    output = BytesIO()
    output.write(("\n".join(traffic_results)).encode('utf-8'))
    output.seek(0)
    logging.info("Traffic results downloaded by user.")
    return send_file(output, as_attachment=True, download_name="traffic_results.txt", mimetype="text/plain")

if __name__ == '__main__':
    load_settings()
    load_cumulative_data()
    app.run(debug=True)
