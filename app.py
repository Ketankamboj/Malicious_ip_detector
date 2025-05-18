from flask import Flask, render_template, request
import pandas as pd
import os
import requests
from werkzeug.utils import secure_filename
from config import API_KEYS, THREAT_INTELLIGENCE_FEEDS
from modules.data_loader import load_data
from modules.signature_detection import check_blacklist
from modules.frequency_analysis import calculate_frequency
from modules.port_analysis import detect_sensitive_ports
from modules.geolocation import enrich_ip_data
from modules.threat_scoring import compute_threat_score
from modules.visualization import generate_map, generate_frequency_plot

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def validate_api_keys():
    """Simplified key validation that actually works"""
    if not API_KEYS.get("IPINFO"):
        raise ValueError("IPINFO key missing in config.py")
    
    key = API_KEYS["IPINFO"].strip()
    if not key or key == "IPINFO":
        raise ValueError("Please replace 'your_ipinfo_api_key' with your actual IPINFO key")


@app.route('/', methods=['GET', 'POST'])
def index():
    analysis = None
    error = None
    validate_api_keys()  # Check API keys on initial load

    try:
        if request.method == 'POST':
            df = process_input()
            analysis = analyze_data(df)
            
    except ValueError as e:
        error = f"Configuration Error: {str(e)}"
    except Exception as e:
        error = f"Analysis Failed: {str(e)}"

    return render_template('index.html', 
                         analysis=analysis,
                         error=error)

def process_input():
    """Handle file upload or IP input"""
    if 'ip_address' in request.form and request.form['ip_address'].strip():
        return handle_ip_input()
    elif 'file' in request.files:
        return handle_file_upload()
    else:
        raise ValueError("Please provide either an IP address or upload a file")

def handle_ip_input():
    """Create DataFrame from single IP input"""
    ip = request.form['ip_address'].strip()
    return pd.DataFrame([{
        'source_ip': ip,
        'timestamp': pd.Timestamp.now(),
        'port': 0,
        'protocol': 'Unknown',
        'packet_size': 0
    }])

def handle_file_upload():
    """Process uploaded network logs file"""
    file = request.files['file']
    if file.filename == '':
        raise ValueError("No file selected")
        
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return load_data(filepath)

def analyze_data(df):
    """Complete analysis pipeline"""
    if df.empty:
        return None

    # Analysis pipeline
    df = check_blacklist(df)
    df = calculate_frequency(df)
    df = detect_sensitive_ports(df)
    df = enrich_ip_data(df)  # Uses IPINFO API key
    df = compute_threat_score(df)

    # Generate results
    return {
        'table': df.to_html(classes='data', index=False),
        'map': generate_map(df),
        'plot': generate_frequency_plot(df),
        'ip_count': len(df['source_ip'].unique()),
        'critical_count': len(df[df['threat_level'] == 'Critical']),
        'warning_count': len(df[df['threat_level'] == 'Warning'])
    }

if __name__ == '__main__':
    try:
        print("🔄 Validating API key...")
        validate_api_keys()
        print("✅ Configuration valid - Starting server...")
        app.run(debug=True)
    except ValueError as e:
        print(f"\n❌ Configuration Error: {str(e)}")
        print(f"Current key value: '{API_KEYS.get('IPINFO')}'")
        print("Get a free key from: https://ipinfo.io/signup")
    except Exception as e:
        print(f"\n⚠️ Unexpected error: {str(e)}")