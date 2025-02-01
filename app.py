from flask import Flask, render_template, request
from helpers.imports import *
from config.patterns import patterns, suspicious_indicators
import webbrowser
from io import BytesIO


app = Flask(__name__)

def classify_email(email_data):
    """
    Classify the email based on attachment safety.
    - If any attachment is 'Malicious', classify as Spam.
    - If all attachments are 'Safe' or no attachments exist, classify as Ham.
    """
    for attachment in email_data.get("attachments", []):
        if attachment["attachment_safe"] == "Malicious":
            return "Spam"
    return "Ham"

def fetch_emails(user, password, start_date, end_date):
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(user, password)
    mail.select("inbox")
    search_criteria = f'(SINCE {start_date.strftime("%d-%b-%Y")} BEFORE {(end_date + timedelta(days=1)).strftime("%d-%b-%Y")})'
    status, messages = mail.search(None, search_criteria)
    if status != 'OK':
        return []
    
    emails = []
    for mail_id in messages[0].split():
        status, msg_data = mail.fetch(mail_id, "(RFC822)")
        if status != 'OK':
            continue
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                from_address = msg.get("From")
                date = msg.get("Date")

                # Check for attachments and scan for vulnerabilities
                attachments = []
                for part in msg.walk():
                    if part.get_content_disposition() == "attachment":
                        filename = part.get_filename()
                        file_content = part.get_payload(decode=True)
                        if filename and file_content:
                            attachment_safe = "Malicious" if check_attachment_malicious(filename, file_content) else "Safe"
                            attachments.append({
                                "filename": filename,
                                "attachment_safe": attachment_safe
                            })
                
                emails.append({
                    "id": mail_id.decode(),
                    "from": from_address,
                    "subject": subject,
                    "date": date,
                    "message": msg.get_payload(decode=True) if msg.is_multipart() else msg.get_payload(),
                    "attachments": attachments
                })
    mail.logout()
    return emails


def check_generic_malicious(file_content, extension):
    """
    Checks file content for suspicious indicators or patterns based on its extension.
    """
    try:
        content = file_content.decode('utf-8', errors='ignore')  # Decode content into text
        if any(indicator in content for indicator in suspicious_indicators):
            return True
        for name, pattern in patterns.items():
            if re.search(pattern, content):
                print(f"Pattern match detected in {extension.upper()} file: {name}")
                return True
        return False
    except Exception as e:
        print(f"Error processing {extension.upper()} file: {e}")
        return False
def check_pdf_malicious(file_content):
    """
    Checks PDF files for suspicious indicators or patterns.
    """
    return check_generic_malicious(file_content, 'pdf')

def check_python_malicious(file_content):
    """
    Checks Python files for suspicious indicators or patterns.
    """
    return check_generic_malicious(file_content, 'py')


def check_vbs_malicious(file_content):
    """
    Checks VBScript files for suspicious indicators or patterns.
    """
    return check_generic_malicious(file_content, 'vbs')


def check_bash_malicious(file_content):
    """
    Checks Bash scripts for suspicious indicators or patterns.
    """
    return check_generic_malicious(file_content, 'bash')

def check_java_malicious(file_content):
    """
    Checks Java files for suspicious indicators or patterns.
    """
    return check_generic_malicious(file_content, 'java')


def check_txt_malicious(file_content):
    """
    Checks Text files for suspicious indicators or patterns.
    """
    return check_generic_malicious(file_content, 'txt')


def check_double_extension(filename):
    parts = filename.split('.')
    dangerous_extensions = ['exe', 'scr', 'js', 'vbs', 'bat', 'cmd', 'pif', 'com', 'dll']
    if len(parts) > 2:
        if parts[-1].lower() in dangerous_extensions or parts[-2].lower() in dangerous_extensions:
            return True
    return False


def check_attachment_malicious(filename, file_content):
    """
    Scans attachments for malicious indicators based on their type and pattern matching.
    """
    if file_content is None:
        return False

    # Decode file content into a string for scanning
    try:
        content = file_content.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error decoding file content: {e}")
        return False

    # Check for double extensions
    if check_double_extension(filename):
        return True

    # File-type specific scanning
    if filename.endswith('.pdf'):
        return check_pdf_malicious(BytesIO(file_content))
    elif filename.endswith('.py'):
        return check_python_malicious(file_content)
    elif filename.endswith('.vbs'):
        return check_vbs_malicious(file_content)
    elif filename.endswith(('.bash', '.sh')):
        return check_bash_malicious(file_content)
    elif filename.endswith('.java'):
        return check_java_malicious(file_content)
    elif filename.endswith('.txt'):
        return check_txt_malicious(file_content)

    # Generic indicator and pattern scanning
    if any(indicator in content for indicator in suspicious_indicators):
        return True
    for name, pattern in patterns.items():
        if re.search(pattern, content):
            print(f"Pattern match detected: {name}")
            return True

    return False


# Helper functions for scanning files (unmodified from the previous code)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_email_route():
    user = request.form['email']
    password = request.form['password']
    start_date = datetime.strptime(request.form['start_date'], "%Y-%m-%d")
    end_date = datetime.strptime(request.form['end_date'], "%Y-%m-%d")

    emails = fetch_emails(user, password, start_date, end_date)
    results = []

    for i, email_data in enumerate(emails, start=1):
        classification = classify_email(email_data)

        results.append({
            "index": i,
            "from": email_data['from'],
            "subject": email_data['subject'],
            "date": email_data['date'],
            "id": email_data["id"],
            "classification": classification,
            "attachments": email_data["attachments"]
        })

    return render_template('results.html', emails=results)

@app.route('/scan/<mail_id>', methods=['POST'])
def scan_email(mail_id):
    email_data = request.form.get("email_data")
    attachments = []
    for key in request.form:
        if key.startswith("attachment_safe_"):
            filename = key.replace("attachment_safe_", "")
            attachment_safe = request.form[key]
            attachments.append({
                "filename": filename,
                "attachment_safe": attachment_safe
            })

    result = classify_email({"attachments": attachments})
    return render_template("scan_result.html", result=result, attachments=attachments)


if __name__ == "__main__":
    # Open the default web browser to the app's URL when the app starts
    webbrowser.open_new_tab("http://localhost:8080/")
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port="8080")
