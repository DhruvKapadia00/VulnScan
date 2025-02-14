"""
VulnScan - Network Vulnerability Scanner
A Flask-based web application that combines Nmap port scanning with the National Vulnerability Database (NVD)
to identify potential security vulnerabilities in network services.

Features:
- Port scanning with service version detection
- Real-time vulnerability lookup using NVD API
- Report generation and management
- Modern dark-themed UI with real-time feedback
"""

from flask import Flask, render_template, request, jsonify, send_file, make_response
from datetime import datetime
import os
import json
import requests
from werkzeug.utils import secure_filename
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'reports'
app.config['NMAP_PATH'] = r"C:\Program Files (x86)\Nmap"

# Ensure reports directory exists
if not os.path.exists('reports'):
    os.makedirs('reports')

def check_nmap_installed():
    """Verify that Nmap is installed and accessible"""
    nmap_exe = os.path.join(app.config['NMAP_PATH'], 'nmap.exe')
    return os.path.isfile(nmap_exe)

class PortScanner:
    """Handles network port scanning using Nmap"""
    
    def __init__(self):
        if not check_nmap_installed():
            raise RuntimeError("Nmap is not installed. Please install Nmap first: https://nmap.org/download.html")
        try:
            import nmap
            os.environ['PATH'] = app.config['NMAP_PATH'] + os.pathsep + os.environ['PATH']
            self.scanner = nmap.PortScanner()
        except ImportError:
            raise RuntimeError("python-nmap module is not properly installed")
    
    def scan_target(self, target):
        """
        Scan a target IP or domain using Nmap
        
        Args:
            target: IP address or domain to scan
            
        Returns:
            dict: Scan results including open ports and service information
            
        Scan options:
            -sV: Version detection
            -sS: TCP SYN scan (stealthy)
            -T4: Aggressive timing template
        """
        try:
            self.scanner.scan(target, arguments='-sV -sS -T4')
            if target in self.scanner.all_hosts():
                return self.scanner[target]
            return {"error": "No hosts found"}
        except Exception as e:
            return {"error": str(e)}

class VulnerabilityChecker:
    """Queries the National Vulnerability Database (NVD) API for known vulnerabilities"""
    
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def check_service_vulnerabilities(self, service_name, version):
        """
        Search for known vulnerabilities for a specific service and version
        
        Args:
            service_name: Name of the service (e.g., 'apache')
            version: Version string of the service
            
        Returns:
            dict: Vulnerability information from NVD
        """
        try:
            params = {
                'keywordSearch': f'{service_name} {version}',
                'resultsPerPage': 5
            }
            response = requests.get(self.nvd_api_url, params=params)
            if response.status_code == 200:
                return response.json()
            return {"error": f"API returned status code {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

@app.route('/')
def index():
    """Serve the main application page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """
    Handle port scanning and vulnerability checking requests
    
    Returns:
        JSON response with scan results or error message
    """
    try:
        target = request.form.get('target')
        if not target:
            return make_response(jsonify({'error': 'No target specified'}), 400)

        # Check if nmap is installed
        if not check_nmap_installed():
            return make_response(
                jsonify({
                    'error': 'Nmap is not installed. Please install Nmap first: https://nmap.org/download.html'
                }), 
                500
            )

        scanner = PortScanner()
        vuln_checker = VulnerabilityChecker()
        
        # Perform scan
        scan_results = scanner.scan_target(target)
        
        # Check for scan errors
        if isinstance(scan_results, dict) and 'error' in scan_results:
            return make_response(jsonify({'error': scan_results['error']}), 500)
        
        # Format results
        formatted_results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ports': []
        }
        
        for proto in scan_results.all_protocols():
            ports = scan_results[proto].keys()
            for port in ports:
                port_info = scan_results[proto][port]
                service_name = port_info.get('name', '')
                version = port_info.get('version', '')
                
                # Check vulnerabilities
                vulns = vuln_checker.check_service_vulnerabilities(service_name, version)
                
                formatted_results['ports'].append({
                    'port': port,
                    'protocol': proto,
                    'service': service_name,
                    'version': version,
                    'state': port_info.get('state', ''),
                    'vulnerabilities': vulns
                })
        
        # Save results
        report_filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
        with open(report_path, 'w') as f:
            json.dump(formatted_results, f, indent=4)
        
        response = make_response(jsonify(formatted_results))
        response.headers['Content-Type'] = 'application/json'
        return response

    except Exception as e:
        app.logger.error(f"Error during scan: {str(e)}")
        return make_response(jsonify({'error': str(e)}), 500)

@app.route('/reports')
def list_reports():
    """
    List available scan reports
    
    Returns:
        JSON response with list of report filenames
    """
    try:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            
        reports = []
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if filename.endswith('.json'):
                reports.append(filename)
        return jsonify(reports)
    except Exception as e:
        app.logger.error(f"Error listing reports: {str(e)}")
        return make_response(jsonify({'error': 'Failed to list reports'}), 500)

@app.route('/download/<filename>')
def download_report(filename):
    """
    Serve a scan report for download
    
    Args:
        filename: Name of the report file to download
    
    Returns:
        Report file as a JSON attachment
    """
    try:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            return make_response(jsonify({'error': 'Reports directory not found'}), 404)
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        if not os.path.exists(file_path):
            return make_response(jsonify({'error': 'Report not found'}), 404)
            
        return send_file(
            file_path,
            as_attachment=True,
            mimetype='application/json',
            download_name=filename
        )
    except Exception as e:
        app.logger.error(f"Error downloading report: {str(e)}")
        return make_response(jsonify({'error': 'Failed to download report'}), 500)

@app.route('/clear-reports', methods=['POST'])
def clear_reports():
    """
    Delete all scan reports from the reports directory
    
    Returns:
        JSON response indicating success or error
    """
    try:
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            # Remove all files in the reports directory
            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            return jsonify({'message': 'All reports cleared successfully'})
        return jsonify({'message': 'No reports to clear'})
    except Exception as e:
        return make_response(jsonify({'error': str(e)}), 500)

if __name__ == '__main__':
    if not check_nmap_installed():
        print("Warning: Nmap is not installed. Please install Nmap first: https://nmap.org/download.html")
    app.run(debug=True)
