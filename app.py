import os
import re
import base64
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from PIL import Image
import io
# Google Cloud Vision disabled for Render deployment
# from google.cloud import vision
from datetime import datetime, timedelta
import jwt
import secrets
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import create_user, get_user_by_email, update_last_login

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
EMAIL_USER = os.environ.get('EMAIL_USER', 'certitrust.verify@gmail.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'your-app-password')
OTP_EXPIRY_MINUTES = 5
JWT_EXPIRY_HOURS = 24

# In-memory OTP storage (for development)
otp_storage = {}  # {email: {otp: '123456', expires: datetime}}

# Try to set tesseract path for Windows
try:
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
except:
    pass

def extract_text_from_image(image_bytes):
    """Use Tesseract OCR to extract text from image"""
    try:
        # Convert bytes to PIL Image
        image = Image.open(io.BytesIO(image_bytes))
        
        # Use Tesseract to extract text
        text = pytesseract.image_to_string(image)
        
        print(f"Extracted text: {text[:500]}")
        return text if text.strip() else None
    except Exception as e:
        print(f"Error in OCR: {str(e)}")
        # Try without specific tesseract path
        try:
            image = Image.open(io.BytesIO(image_bytes))
            text = pytesseract.image_to_string(image)
            return text if text.strip() else None
        except:
            return None

def extract_text_from_pdf(pdf_bytes):
    """Convert PDF to images and extract text using OCR"""
    try:
        print(f"Attempting to open PDF, size: {len(pdf_bytes)} bytes")
        # Open PDF from bytes using PyMuPDF
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        print(f"PDF opened successfully, {len(pdf_document)} pages found")
        
        all_text = []
        for page_num in range(len(pdf_document)):
            print(f"Processing PDF page {page_num + 1}/{len(pdf_document)}")
            
            # Get the page
            page = pdf_document[page_num]
            
            # First, try to extract text directly (works for text-based PDFs)
            direct_text = page.get_text()
            if direct_text and direct_text.strip():
                print(f"Page {page_num + 1}: Extracted {len(direct_text)} chars via direct text extraction")
                all_text.append(direct_text)
                continue
            
            # If no direct text, render to image and use OCR (for scanned PDFs)
            print(f"Page {page_num + 1}: No direct text found, using OCR")
            try:
                # Render page to image (pixmap)
                pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))  # 2x zoom for better quality
                
                # Convert pixmap to PIL Image
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                
                # Convert PIL Image to bytes
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_bytes = img_byte_arr.getvalue()
                
                # Extract text from this page
                text = extract_text_from_image(img_bytes)
                if text:
                    print(f"Page {page_num + 1}: Extracted {len(text)} chars via OCR")
                    all_text.append(text)
            except Exception as ocr_err:
                print(f"OCR failed for page {page_num + 1}: {str(ocr_err)}")
        
        pdf_document.close()
        
        combined_text = '\n\n'.join(all_text)
        print(f"Total extracted text: {len(combined_text)} characters")
        print(f"First 500 chars: {combined_text[:500]}")
        return combined_text if combined_text.strip() else None
    except Exception as e:
        print(f"!!! ERROR processing PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def extract_urls(text):
    """Extract URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    
    # Also look for domain patterns without protocol
    domain_pattern = r'\b(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b'
    domains = re.findall(domain_pattern, text)
    
    # Add http:// to domains if not already URLs
    for domain in domains:
        if not any(domain in url for url in urls):
            urls.append(f"https://{domain}")
    
    return list(set(urls))

def scrape_website(url):
    """Scrape website content"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Clean up text
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as e:
        print(f"Error scraping {url}: {str(e)}")
        return None

def extract_names_with_gemini(text):
    """Extract person names using simple pattern matching"""
    try:
        # Simple name pattern: Capitalized words (2-4 words)
        # Looks for patterns like "John Smith" or "Dr. Jane Doe"
        name_pattern = r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b'
        
        potential_names = re.findall(name_pattern, text)
        
        # Filter out common words and short matches
        stop_words = {'The', 'This', 'That', 'These', 'Those', 'Certificate', 'Award', 
                      'Course', 'Program', 'University', 'College', 'Institute', 'School',
                      'Department', 'Has', 'Have', 'Been', 'Successfully', 'Completed'}
        
        names = []
        for name in potential_names:
            words = name.split()
            if len(words) >= 2 and not any(word in stop_words for word in words):
                if name not in names:  # Avoid duplicates
                    names.append(name)
        
        print(f"Extracted names: {names}")
        return names[:10]  # Limit to first 10 names
    except Exception as e:
        print(f"Error extracting names: {str(e)}")
        return []

def fuzzy_match_names(name1, name2):
    """Simple fuzzy matching for names"""
    name1 = name1.lower().strip()
    name2 = name2.lower().strip()
    
    # Exact match
    if name1 == name2:
        return 100
    
    # Check if one name contains the other
    if name1 in name2 or name2 in name1:
        return 80
    
    # Split into words and check overlap
    words1 = set(name1.split())
    words2 = set(name2.split())
    
    if words1 & words2:  # If there's any overlap
        overlap = len(words1 & words2)
        total = len(words1 | words2)
        return int((overlap / total) * 100)
    
    return 0

def verify_certificate(certificate_text, website_text):
    """Compare names from certificate and website"""
    cert_names = extract_names_with_gemini(certificate_text)
    web_names = extract_names_with_gemini(website_text)
    
    print(f"Certificate names: {cert_names}")
    print(f"Website names: {web_names}")
    
    if not cert_names:
        return {
            'status': 'suspicious',
            'reason': 'No names found in certificate',
            'cert_names': [],
            'web_names': web_names,
            'matches': []
        }
    
    if not web_names:
        return {
            'status': 'suspicious',
            'reason': 'No names found on linked website',
            'cert_names': cert_names,
            'web_names': [],
            'matches': []
        }
    
    # Find best matches
    matches = []
    for cert_name in cert_names:
        best_match = None
        best_score = 0
        
        for web_name in web_names:
            score = fuzzy_match_names(cert_name, web_name)
            if score > best_score:
                best_score = score
                best_match = web_name
        
        if best_match:
            matches.append({
                'cert_name': cert_name,
                'web_name': best_match,
                'score': best_score
            })
    
    # Determine if verified (at least one good match with score > 70)
    verified = any(match['score'] > 70 for match in matches)
    
    return {
        'status': 'pass' if verified else 'suspicious',
        'reason': 'Name match found' if verified else 'No matching names found',
        'cert_names': cert_names,
        'web_names': web_names,
        'matches': matches
    }

@app.route('/api/verify-certificate', methods=['POST'])
def verify_certificate_endpoint():
    """Main endpoint for certificate verification"""
    try:
        # Check if file is present
        if 'certificate' not in request.files:
            return jsonify({'error': 'No certificate file provided'}), 400
        
        file = request.files['certificate']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file bytes
        image_bytes = file.read()
        
        # Check if it's a PDF or image
        file_type = file.content_type
        
        # Step 1: Extract text using appropriate method
        print(f"Processing file type: {file_type}")
        if file_type == 'application/pdf':
            print("Extracting text from PDF...")
            certificate_text = extract_text_from_pdf(image_bytes)
        else:
            print("Extracting text from image...")
            certificate_text = extract_text_from_image(image_bytes)
        
        if not certificate_text:
            return jsonify({'error': 'Failed to extract text from certificate'}), 500
        
        print(f"Extracted text: {certificate_text[:500]}...")
        
        # Step 2: Extract URLs from certificate
        print("Extracting URLs...")
        urls = extract_urls(certificate_text)
        
        if not urls:
            return jsonify({
                'status': 'suspicious',
                'reason': 'No URLs found in certificate',
                'certificate_text': certificate_text,
                'urls': []
            })
        
        print(f"Found URLs: {urls}")
        
        # Step 3: Scrape the first URL found
        website_text = None
        scraped_url = None
        
        for url in urls[:3]:  # Try first 3 URLs
            print(f"Scraping {url}...")
            website_text = scrape_website(url)
            if website_text:
                scraped_url = url
                break
        
        if not website_text:
            return jsonify({
                'status': 'suspicious',
                'reason': 'Could not access any URLs found in certificate',
                'certificate_text': certificate_text,
                'urls': urls
            })
        
        print(f"Scraped {len(website_text)} characters from {scraped_url}")
        
        # Step 4: Verify names match
        print("Verifying names...")
        verification_result = verify_certificate(certificate_text, website_text)
        
        # Add additional context
        verification_result['certificate_text'] = certificate_text[:1000]
        verification_result['urls'] = urls
        verification_result['scraped_url'] = scraped_url
        
        return jsonify(verification_result)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Authentication Helper Functions
def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def mask_mobile(mobile):
    """Mask mobile number for display"""
    if len(mobile) >= 4:
        return '*' * (len(mobile) - 3) + mobile[-3:]
    return mobile

def require_auth(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            # Verify token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user_mobile = payload['mobile']
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated

# Authentication Endpoints
def send_email_otp(email, otp):
    """Send OTP via email using Gmail SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Your Certi-Trust OTP: {otp}'
        msg['From'] = EMAIL_USER
        msg['To'] = email
        
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #ff8c00; text-align: center;">Certi-Trust Verification</h2>
                <p style="font-size: 16px; color: #333;">Hello,</p>
                <p style="font-size: 16px; color: #333;">Your One-Time Password (OTP) for Certi-Trust is:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <span style="font-size: 32px; font-weight: bold; color: #ff6600; letter-spacing: 8px; padding: 15px 30px; border: 2px dashed #ffa726; border-radius: 8px; display: inline-block;">
                        {otp}
                    </span>
                </div>
                <p style="font-size: 14px; color: #666;">This OTP will expire in <strong>5 minutes</strong>.</p>
                <p style="font-size: 14px; color: #666;">If you didn't request this OTP, please ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 12px; color: #999; text-align: center;">Certi-Trust - Your AI Certificate Verifier</p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False

@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    """Send OTP to email"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email or '@' not in email:
            return jsonify({'error': 'Invalid email address'}), 400
        
        otp = generate_otp()
        expires = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
        
        otp_storage[email] = {
            'otp': otp,
            'expires': expires
        }
        
        email_sent = send_email_otp(email, otp)
        
        if not email_sent:
            print(f"\n{'='*50}")
            print(f"OTP for {email}: {otp}")
            print(f"Expires at: {expires.strftime('%H:%M:%S')}")
            print(f"{'='*50}\n")
        
        return jsonify({
            'message': 'OTP sent to your email' if email_sent else 'Check console for OTP',
            'expires_in': OTP_EXPIRY_MINUTES * 60
        })
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': 'Failed to send OTP'}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP and create/login user"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        otp = data.get('otp', '').strip()
        
        if not email or not otp:
            return jsonify({'error': 'Email and OTP are required'}), 400
        
        if email not in otp_storage:
            return jsonify({'error': 'No OTP found. Please request a new one.'}), 400
        
        stored_data = otp_storage[email]
        
        if datetime.now() > stored_data['expires']:
            del otp_storage[email]
            return jsonify({'error': 'OTP expired. Please request a new one.'}), 400
        
        if otp != stored_data['otp']:
            return jsonify({'error': 'Invalid OTP'}), 400
        
        del otp_storage[email]
        
        user = get_user_by_email(email)
        is_new_user = False
        
        if not user:
            create_user(email)
            is_new_user = True
        else:
            update_last_login(email)
        
        token_payload = {
            'email': email,
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
        }
        token = jwt.encode(token_payload, SECRET_KEY, algorithm='HS256')
        
        return jsonify({
            'token': token,
            'email': email,
            'is_new_user': is_new_user,
            'message': 'Login successful'
        })
    
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        return jsonify({'error': 'Failed to verify OTP'}), 500

@app.route('/api/auth/verify-token', methods=['GET'])
def verify_token():
    """Verify if token is still valid"""
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'valid': False, 'error': 'No token provided'}), 401
    
    try:
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        return jsonify({
            'valid': True,
            'email': payload.get('email', payload.get('mobile', ''))
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'ocr': 'tesseract'})

if __name__ == '__main__':
    print("Starting Flask server with Tesseract OCR...")
    app.run(debug=True, port=5000)
