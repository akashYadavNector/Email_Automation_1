import os
import logging
import time
import email
import imaplib
import ssl
from email import message_from_bytes
from email.header import decode_header
from bs4 import BeautifulSoup
import json
import re

# Settings
EMAIL_USER = 'mypurna.test@mypurna.com'  # Replace with your email address
EMAIL_PASSWORD = 'Purna@123'  # Replace with your email password
IMAP_SERVER = 'imap.hostinger.com'
IMAP_PORT = 993

# Logging setup
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    # filename='email_organization.log'
)

# Categories and keywords (expanded for better B2B and business recognition)
CATEGORY_KEYWORDS = {
    "To Respond": [
        r"urgent|please\s+reply|action\s+required|respond|reply\s+needed|action\s+needed",
        r"need\s+response|reply\s+urgent|follow\s+up|quotation|inquiry\s+about\s+service"
    ],
    "B2B Query": [  # New category specifically for B2B
        r"partnership|collaboration|business\s+opportunity|vendor|supplier|quote\s+request",
        r"service\s+inquiry|bulk\s+order|wholesale|contract|proposal|business\s+proposal",
        r"enterprise\s+solution|business\s+query|client\s+request|request\s+for\s+quote"
    ],
    "Business Critical": [  # New category for important business matters
        r"contract|agreement|payment|invoice|deadline|project\s+timeline|deliverable",
        r"executive|stakeholder|customer\s+complaint|escalation|critical\s+issue|revenue"
    ],
    "FYI": [
        r"for\s+your\s+information|info|update|just\s+info|note|for\s+info"
    ],
    "Comment": [
        r"feedback|opinion|thoughts|suggestion|review|comment|input"
    ],
    "Notification": [
        r"alert|notice|reminder|notification|alerted|notify"
    ],
    "Meeting Update": [
        r"meeting|schedule|call|agenda|meeting\s+update|conference|meeting\s+schedule"
    ],
    "Awaiting Reply": [
        r"waiting|response|follow\s+up|awaiting|pending\s+reply|waiting\s+for\s+response"
    ],
    "Actioned": [
        r"done|completed|resolved|finished|actioned|task\s+completed"
    ],
    "Marketing": [
        r"offer|promo|sale|discount|promotion|advertisement|marketing\s+offer"
    ],
    "Developer/Testing": [
        r"bug|test|code|development|debug|qa|testing|developer\s+note"
    ],
    "General Inquiry": [  # Renamed from "General" to "General Inquiry"
        r"question|inquiry|help|ask|need\s+assistance|query|support\s+needed|general\s+question"
    ]
}
CATEGORIES = list(CATEGORY_KEYWORDS.keys())

# Enhanced importance determination with B2B and business focus
IMPORTANCE_KEYWORDS = {
    "High": [
        r"urgent|important|asap|priority|critical|deadline|immediately|emergency",
        r"contract|payment|invoice|executive|ceo|director|stakeholder|partner",
        r"revenue|opportunity|contract|deal|agreement|dispute|complaint|escalation"
    ],
    "Normal": []  # Default importance
}

def create_connection():
    logging.info("Attempting to create IMAP connection to %s...", IMAP_SERVER)
    try:
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, ssl_context=context, timeout=30)
        mail.login(EMAIL_USER, EMAIL_PASSWORD)
        logging.info("Successfully connected and logged in to IMAP server.")
        return mail
    except Exception as e:
        logging.error("Failed to create IMAP connection: %s", e)
        raise

def logout(mail):
    logging.info("Logging out from IMAP server...")
    try:
        mail.logout()
        logging.info("Successfully logged out.")
    except Exception as e:
        logging.error("Failed to log out: %s", e)

def decode_subject(encoded_subject):
    logging.debug("Decoding subject: %s", encoded_subject)
    decoded_subject, charset = decode_header(encoded_subject)[0]
    if isinstance(decoded_subject, bytes):
        decoded_subject = decoded_subject.decode(charset if charset else 'utf-8', errors='ignore')
    return decoded_subject

def clean_html_body(html_body):
    logging.debug("Cleaning HTML body...")
    soup = BeautifulSoup(html_body, "html.parser")
    return soup.get_text()

def determine_importance(email):
    logging.debug("Determining importance for email with subject: %s", email["subject"])
    text = (email["subject"] + " " + email["body"]).lower()
    
    # Check for high importance keywords
    for keyword in IMPORTANCE_KEYWORDS["High"]:
        if re.search(keyword, text):
            logging.debug("Email marked as High importance due to keyword: %s", keyword)
            return "High"
    
    # Check for business email domains which might indicate importance
    sender = email.get("from", "").lower()
    business_domains = [".com", ".org", ".net", ".co", ".io", ".gov", ".edu"]
    if any(domain in sender for domain in business_domains) and not re.search(r"newsletter|noreply|marketing|info@", sender):
        if re.search(r"proposal|quote|inquiry|request|partnership", text):
            logging.debug("Email marked as High importance due to business sender and content")
            return "High"
    
    return "Normal"

def classify_emails_into_categories(emails, categories):
    logging.info("Classifying %d emails into categories...", len(emails))
    categorized_emails = {category: [] for category in categories}
    
    for email in emails:
        text = (email["subject"] + " " + email["body"]).lower()
        assigned = False
        
        # First priority: Check for B2B Query and Business Critical categories
        for priority_category in ["B2B Query", "Business Critical"]:
            if priority_category in CATEGORY_KEYWORDS:
                keywords = CATEGORY_KEYWORDS[priority_category]
                if any(re.search(keyword, text) for keyword in keywords):
                    email["category"] = priority_category
                    email["importance"] = "High"  # Force high importance for these categories
                    categorized_emails[priority_category].append(email)
                    logging.debug("Email '%s' classified as %s (Importance: High, Priority category)", 
                                 email["subject"], priority_category)
                    assigned = True
                    break
        
        # If not assigned to priority categories, check remaining ones
        if not assigned:
            for category, keywords in CATEGORY_KEYWORDS.items():
                if category not in ["B2B Query", "Business Critical"] and any(re.search(keyword, text) for keyword in keywords):
                    email["category"] = category
                    email["importance"] = determine_importance(email)
                    categorized_emails[category].append(email)
                    logging.debug("Email '%s' classified as %s (Importance: %s)", 
                                email["subject"], category, email["importance"])
                    assigned = True
                    break
        
        # Default classification if nothing matched
        if not assigned:
            email["category"] = "To Respond"  # Default category
            email["importance"] = determine_importance(email)
            categorized_emails["To Respond"].append(email)
            logging.debug("Email '%s' classified as To Respond (Default, Importance: %s)", 
                        email["subject"], email["importance"])
    
    logging.info("Classification complete. Categories: %s", list(categorized_emails.keys()))
    return categorized_emails

def sanitize_folder_name(folder_name):
    # Remove or replace special characters and spaces
    return re.sub(r'[\s/]', '_', folder_name)

def create_folder(mail, folder_name):
    logging.info("Attempting to create folder: %s", folder_name)
    
    # Sanitize folder name
    sanitized_name = sanitize_folder_name(folder_name)
    
    # Create parent folder first if it's a path
    if "/" in folder_name:
        parent_folder = folder_name.split("/")[0]
        parent_sanitized = sanitize_folder_name(parent_folder)
        if not parent_sanitized.startswith("INBOX."):
            parent_full = f"INBOX.{parent_sanitized}"
        else:
            parent_full = parent_sanitized
            
        try:
            status, _ = mail.create(parent_full)
            logging.info("Parent folder '%s' creation attempt: %s", parent_full, status)
        except imaplib.IMAP4.error as e:
            if 'ALREADYEXISTS' not in str(e):
                logging.warning("Error creating parent folder: %s", e)
    
    # Ensure the folder name has INBOX. prefix
    if not sanitized_name.startswith("INBOX."):
        full_folder_name = f"INBOX.{sanitized_name}"
    else:
        full_folder_name = sanitized_name
    
    try:
        # Check if folder exists
        status, folders = mail.list()
        folder_exists = False
        
        if status == "OK":
            for folder in folders:
                if folder and full_folder_name.encode() in folder:
                    folder_exists = True
                    logging.info("Folder '%s' already exists.", full_folder_name)
                    break
        
        # Create folder if it doesn't exist
        if not folder_exists:
            try:
                status, response = mail.create(full_folder_name)
                if status == "OK":
                    logging.info("Folder '%s' created successfully.", full_folder_name)
                else:
                    logging.warning("Folder creation returned: %s - %s", status, response)
            except imaplib.IMAP4.error as e:
                if 'ALREADYEXISTS' in str(e):
                    logging.info("Folder '%s' already exists (from exception).", full_folder_name)
                else:
                    logging.error("Error creating folder '%s': %s", full_folder_name, e)
                    # Continue anyway to attempt moving the email
    except Exception as e:
        logging.error("Error in folder creation: %s", e)
        # Continue with the script despite folder creation issues

def get_separator(mail):
    logging.debug("Determining IMAP folder separator...")
    try:
        status, folder_list = mail.list()
        if status == "OK":
            for folder in folder_list:
                if folder:
                    parts = folder.decode().split('"')
                    if len(parts) > 1:
                        separator = parts[1]
                        logging.debug("Found separator: %s", separator)
                        return separator
        logging.warning("Could not determine separator, using '/'")
    except Exception as e:
        logging.error("Error getting separator: %s", e)
    return "/"

def save_emails_to_json(categorized_emails, file_name="emails_by_category.json"):
    """Save categorized emails to a JSON file for auditing."""
    logging.info("Saving categorized emails to JSON file: %s", file_name)
    categorized_data = {}
    for category, email_list in categorized_emails.items():
        categorized_data[category] = []
        for email in email_list:
            categorized_data[category].append({
                "subject": email["subject"],
                "body": email["body"],
                "importance": email["importance"]
            })
    try:
        with open(file_name, 'w') as json_file:
            json.dump(categorized_data, json_file, indent=4)
        logging.info("Emails successfully saved to %s", file_name)
    except Exception as e:
        logging.error("Failed to save emails to JSON: %s", e)

def create_all_category_folders(mail):
    """Pre-create all category folders to ensure they exist"""
    logging.info("Pre-creating all category folders...")
    separator = get_separator(mail)
    
    for category in CATEGORIES:
        # Create main category folder
        folder_name = sanitize_folder_name(category)
        if not folder_name.startswith("INBOX."):
            full_folder_name = f"INBOX.{folder_name}"
        else:
            full_folder_name = folder_name
            
        try:
            mail.create(full_folder_name)
            logging.info("Created category folder: %s", full_folder_name)
        except imaplib.IMAP4.error as e:
            if 'ALREADYEXISTS' not in str(e):
                logging.warning("Error creating category folder %s: %s", full_folder_name, e)
        
        # Create High and Normal subfolders
        for importance in ["High", "Normal"]:
            importance_folder = f"{category}{separator}{importance}"
            sanitized = sanitize_folder_name(importance_folder)
            if not sanitized.startswith("INBOX."):
                full_importance_folder = f"INBOX.{sanitized}"
            else:
                full_importance_folder = sanitized
                
            try:
                mail.create(full_importance_folder)
                logging.info("Created importance folder: %s", full_importance_folder)
            except imaplib.IMAP4.error as e:
                if 'ALREADYEXISTS' not in str(e):
                    logging.warning("Error creating importance folder %s: %s", full_importance_folder, e)

def move_email_to_folder(mail, email_id, category, importance):
    logging.info("Moving email ID %s to folder %s/%s", email_id, category, importance)
    separator = get_separator(mail)
    folder_name = f"{category}{separator}{importance}"
    
    # Sanitize folder name
    sanitized_name = sanitize_folder_name(folder_name)
    
    # Ensure INBOX. prefix
    if not sanitized_name.startswith("INBOX."):
        full_folder_name = f"INBOX.{sanitized_name}"
    else:
        full_folder_name = sanitized_name
    
    # Ensure the folder exists
    create_folder(mail, full_folder_name)
    
    try:
        mail.select("INBOX")
        
        # Try MOVE command first if available
        try:
            status, response = mail.uid('MOVE', email_id, full_folder_name)
            if status == "OK":
                logging.info("Successfully moved email ID %s to folder '%s'", email_id, full_folder_name)
                return True
        except (imaplib.IMAP4.error, AttributeError) as e:
            logging.debug("MOVE command failed or not supported: %s. Trying COPY+DELETE...", e)
        
        # Fall back to COPY + DELETE
        status, response = mail.uid('COPY', email_id, full_folder_name)
        if status == "OK":
            # Mark the original for deletion
            mail.uid('STORE', email_id, '+FLAGS', '\\Deleted')
            # Expunge to actually delete
            mail.expunge()
            logging.info("Successfully copied and deleted email ID %s to folder '%s'", email_id, full_folder_name)
            return True
        else:
            logging.error("Failed to copy email ID %s: %s", email_id, response)
            return False
            
    except Exception as e:
        logging.error("Error moving email ID %s: %s", email_id, e)
        return False

def extract_sender_info(msg):
    """Extract sender email and name for better categorization"""
    sender = msg.get("from", "")
    if not sender:
        return {"email": "", "name": ""}
    
    # Try to extract email and name
    match = re.search(r'<([^>]+)>', sender)
    if match:
        email = match.group(1).lower()
        name_part = sender.split('<')[0].strip()
        if name_part.endswith('"'):
            name_part = name_part.strip('"')
        return {"email": email, "name": name_part}
    else:
        return {"email": sender.lower(), "name": ""}

def read_and_process_email(mail, email_id):
    logging.info("Processing email ID: %s", email_id)
    try:
        # Fetch the email
        status, email_data = mail.uid('FETCH', email_id, "(RFC822)")
        if status != "OK":
            logging.warning("Failed to fetch email ID %s: %s", email_id, email_data)
            return None
            
        for response_part in email_data:
            if isinstance(response_part, tuple):
                raw_email = response_part[1]
                msg = message_from_bytes(raw_email)
                
                # Extract basic info
                subject = decode_subject(msg["subject"]) if msg["subject"] else ""
                sender_info = extract_sender_info(msg)
                
                # Extract body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        
                        # Skip attachments
                        if "attachment" in content_disposition:
                            continue
                            
                        # Get text content first, then HTML if no text
                        if content_type == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode("utf-8", errors='ignore')
                                break  # Prefer plain text when available
                            except UnicodeDecodeError:
                                body = part.get_payload(decode=True).decode("latin-1", errors='ignore')
                        elif content_type == "text/html" and not body:
                            try:
                                html_body = part.get_payload(decode=True).decode("utf-8", errors='ignore')
                                body = clean_html_body(html_body)
                            except UnicodeDecodeError:
                                html_body = part.get_payload(decode=True).decode("latin-1", errors='ignore')
                                body = clean_html_body(html_body)
                else:
                    try:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors='ignore')
                    except (UnicodeDecodeError, AttributeError):
                        try:
                            body = msg.get_payload(decode=True).decode("latin-1", errors='ignore')
                        except:
                            body = ""
                
                # Clean HTML if needed
                if body and ("<html" in body.lower() or "<body" in body.lower()):
                    body = clean_html_body(body)
                
                # Prepare email data structure with more metadata
                email_data = {
                    "subject": subject, 
                    "body": body, 
                    "timestamp": msg["date"] if msg["date"] else "",
                    "email_id": email_id.decode(),
                    "from": sender_info["email"],
                    "sender_name": sender_info["name"],
                    "to": msg.get("to", ""),
                    "cc": msg.get("cc", ""),
                    "has_attachments": any("attachment" in str(part.get("Content-Disposition", "")) for part in msg.walk())
                }
                
                # Improved classification with additional metadata
                # Check first for business signals in sender domain and subject
                sender_domain = sender_info["email"].split('@')[-1] if '@' in sender_info["email"] else ""
                is_business_domain = bool(re.search(r'\.com$|\.org$|\.net$|\.co$|\.io$', sender_domain))
                contains_business_terms = bool(re.search(r'quote|proposal|inquiry|request|order|invoice|contract', subject.lower() + " " + body[:200].lower()))
                
                # B2B detection logic
                if is_business_domain and contains_business_terms:
                    email_data["category"] = "B2B Query"
                    email_data["importance"] = "High"
                    logging.info("Email classified as B2B Query (High) based on business signals")
                else:
                    # Standard classification
                    categorized = classify_emails_into_categories([email_data], CATEGORIES)
                    for category, emails in categorized.items():
                        if emails and emails[0]["email_id"] == email_data["email_id"]:
                            email_data["category"] = emails[0]["category"] 
                            email_data["importance"] = emails[0]["importance"]
                            break
                
                # Move the email to the appropriate folder
                move_result = move_email_to_folder(mail, email_id, email_data["category"], email_data["importance"])
                if move_result:
                    logging.info("Email ID %s classified as %s (Importance: %s) and moved successfully", 
                               email_id.decode(), email_data["category"], email_data["importance"])
                else:
                    logging.warning("Failed to move Email ID %s", email_id.decode())
                
                return email_data
    except Exception as e:
        logging.error("Error processing email ID %s: %s", email_id, e)
        return None

def main():
    logging.info("Starting enhanced email organization process...")
    mail = None
    try:
        mail = create_connection()
        
        # First, ensure all category folders exist
        create_all_category_folders(mail)
        
        # Select INBOX to process emails
        mail.select("INBOX")
        status, email_ids = mail.uid('SEARCH', None, 'ALL')
        
        if status != "OK":
            logging.error("Failed to search emails: %s", email_ids)
            return
        
        # Get all email IDs
        email_id_list = email_ids[0].split()
        
        if not email_id_list:
            logging.info("No emails found in INBOX.")
            return
            
        logging.info("Found %d emails in INBOX", len(email_id_list))
        
        processed_count = 0
        success_count = 0
        BATCH_SIZE = 50  # Process in smaller batches
        
        # Process emails in batches
        for i in range(0, len(email_id_list), BATCH_SIZE):
            batch_ids = email_id_list[i:i + BATCH_SIZE]
            logging.info("Processing batch %d to %d of %d emails", 
                       i+1, min(i+BATCH_SIZE, len(email_id_list)), len(email_id_list))
            
            for email_id in batch_ids:
                processed_count += 1
                try:
                    email = read_and_process_email(mail, email_id)
                    if email:
                        success_count += 1
                        if processed_count % 10 == 0:
                            logging.info("Progress: Processed %d of %d emails. Success: %d", 
                                       processed_count, len(email_id_list), success_count)
                except Exception as e:
                    logging.error("Error processing email ID %s: %s", email_id, e)
                    continue
            
            # Short pause between batches to prevent server throttling
            time.sleep(1)
        # Save categorized emails to JSON for auditing (using your existing function)
        categorized_emails = {}
        for category in CATEGORIES:
            categorized_emails[category] = [e for e in (read_and_process_email(mail, eid) for eid in email_id_list if eid) 
                                          if e and e["category"] == category]
        save_emails_to_json(categorized_emails)
        
        logging.info("Email organization process completed. Processed %d emails, %d successfully categorized.", 
                   processed_count, success_count)
        
    except Exception as e:
        logging.error("Error in main process: %s", e)
    finally:
        if mail:
            logout(mail)

if __name__ == "__main__":
    main()