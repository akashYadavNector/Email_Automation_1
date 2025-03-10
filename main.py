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
from openai import OpenAI  # Updated import for the new APIfrom typing import Dict, List, Optional
from typing import Dict, List, Optional  # Add this line
from dotenv import load_dotenv

load_dotenv()

# Configure OpenAI
OPENAI_KEY = os.getenv("OPENAI_KEY")

# Settings
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER")
IMAP_PORT = os.getenv("IMAP_PORT")

# Initialize the OpenAI client (ensure your API key is set in gitthe environment or here)
client = OpenAI(api_key=OPENAI_KEY)  # Replace with your key or set via environment variable

# Logging setup
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

CATEGORIES = [
    "To Respond - Urgent", "To Respond - Questions", "To Respond - Requests", "To Respond - Follow-Ups",
    "B2B Query - Sales", "B2B Query - Support",  "B2B Query - Partnerships", "B2B Query - Billing",
    "FYI - Updates", "FYI - Newsletters", "FYI - Announcements", "FYI - Receipts",
    "Notification - Alerts", "Notification - Confirmations", "Notification - Subscriptions", "Notification - OTP",
    "Meeting Update - Invites", "Meeting Update - Reschedules", "Meeting Update - Cancellations", "Meeting Update - Recaps",
    "Awaiting Reply - Sent Requests", "Awaiting Reply - Pending Approvals", "Awaiting Reply - Follow-Up Reminders", "Awaiting Reply - Delayed Responses",
    "Marketing - Offers", "Marketing - Campaigns", "Marketing - Surveys", "Marketing - Ads",
    "General Inquiry - Personal", "General Inquiry - Unsolicited", "General Inquiry - Info Requests", "General Inquiry - Miscellaneous"
]

EMAIL_COUNT = 0

# Constants for optimization
MAX_THREAD_CHARS = 2000  # Truncate long threads to stay within token limits
BATCH_SIZE = 50
FETCH_DELAY = 1  # 5-second delay per email for rate limits

def create_connection() -> imaplib.IMAP4_SSL:
    """Establish a secure IMAP connection."""
    logging.info(f"Attempting to create IMAP connection to {IMAP_SERVER}...")
    try:
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, ssl_context=context, timeout=30)
        mail.login(EMAIL_USER, EMAIL_PASSWORD)
        logging.info("Successfully connected and logged in to IMAP server.")
        return mail
    except Exception as e:
        logging.error(f"Failed to create IMAP connection: {e}")
        raise

def logout(mail: imaplib.IMAP4_SSL) -> None:
    """Log out from the IMAP server."""
    logging.info("Logging out from IMAP server...")
    try:
        mail.logout()
        logging.info("Successfully logged out.")
    except Exception as e:
        logging.error(f"Failed to log out: {e}")

def decode_subject(encoded_subject: str) -> str:
    """Decode an email subject, handling different charsets."""
    logging.debug(f"Decoding subject: {encoded_subject}")
    try:
        decoded_subject, charset = decode_header(encoded_subject)[0]
        return decoded_subject.decode(charset if charset else 'utf-8', errors='ignore') if isinstance(decoded_subject, bytes) else str(decoded_subject)
    except Exception as e:
        logging.warning(f"Failed to decode subject: {e}")
        return ""

def clean_html_body(html_body: str) -> str:
    """Clean HTML content from an email body, extracting plain text."""
    logging.debug("Cleaning HTML body...")
    try:
        soup = BeautifulSoup(html_body, "html.parser")
        return soup.get_text(strip=True)
    except Exception as e:
        logging.warning(f"Failed to clean HTML body: {e}")
        return ""

def classify_email(email: Dict, categories: List[str]) -> str:
    """Classify email into a category and subcategory using a single OpenAI API call with refined rules."""
    logging.debug(f"Classifying email with subject: {email['subject']}")
    text = (email["subject"] + " " + email["body"]).lower()[:2000]  # Truncate for token limits
    
    # # Pre-check for no-reply senders (keep this for efficiency)
    # if "donotreply" in email["from"].lower() or "noreply" in email["from"].lower():
    #     if "please respond" in text or "action required" in text:
    #         return "To Respond - Urgent"  # Assuming urgency for rare actionable no-reply emails
    #     return "Notification - Confirmations"  # Default to a common notification type
    
    # # Pre-check for OTP/system-generated (optional, but speeds up obvious cases)
    # if any(keyword in text for keyword in ["otp", "one-time password", "system generated", "do not reply"]):
    #     if "please respond" in text or "action required" in text:
    #         return "To Respond - Urgent"
    #     return "Notification - OTP"  # Specific to OTPs
    
    prompt = f"""
    Classify the following email text into one of these categories with subcategories: {', '.join(categories)}.
    Respond with ONLY the combined category-subcategory name (e.g., 'To Respond - Urgent') and nothing else.
    Use the following strict definitions to determine the category and subcategory:

    - 'To Respond': The email explicitly requires a response or action from the recipient.
      - 'Urgent': Time-sensitive requests with explicit deadlines (e.g., "Need by EOD," "ASAP," "urgent," "immediately").
      - 'Questions': Asks for clarification (e.g., "Can you confirm?").
      - 'Requests': Assigns a task (e.g., "Please review").
      - 'Follow-Ups': Continues a conversation (e.g., "Any updates?").
    - 'B2B Query': Business-to-business inquiry or request.
      - 'Sales': Vendor/client transactions (e.g., "quote," "order").
      - 'Support': Technical/service help (e.g., "fix," "how to").
      - 'Partnerships': Collaboration offers (e.g., "partner," "joint").
      - 'Billing': Payment-related (e.g., "invoice," "charge").
    - 'FYI':  Human-written information for awareness, no action required..
      - 'Updates': Business/project status reports from colleagues (e.g., "The project is 75% complete").
      - 'Newsletters': Curated content digests with multiple topics (e.g., "This week's industry news").
      - 'Announcements': Human-composed organizational announcements (e.g., "New office policy").
      - 'Receipts': Purchase or transaction documentation (e.g., "Your payment receipt").
    - 'Notification': System-generated or automated messages.
      - 'Alerts': Time-sensitive automated warnings (e.g., "Server downtime in 1 hour").
      - 'Confirmations': Automated acknowledgments of user actions (e.g., "Password reset complete").
      - 'Subscriptions': Automated updates from services you've subscribed to (e.g., "New content available").
      - 'OTP': Security codes and verification messages (e.g., "Your verification code is 123456").
    - 'Meeting Update': Related to scheduling or meetings.
      - 'Invites': New meetings (e.g., "join us," "invite").
      - 'Reschedules': Changes (e.g., "moved," "rescheduled").
      - 'Cancellations': Cancelled events (e.g., "off," "cancelled").
      - 'Recaps': Post-meeting notes (e.g., "summary," "minutes").
    - 'Awaiting Reply': Sender waiting for your response.
      - 'Sent Requests': Your outbound requests (e.g., "Can you send?").
      - 'Pending Approvals': Awaiting sign-off (e.g., "approve").
      - 'Follow-Up Reminders': Nudges (e.g., "checking in").
      - 'Delayed Responses': Overdue (e.g., "still waiting").
    - 'Marketing': Promotional content.
      - 'Offers': Deals (e.g., "discount," "sale").
      - 'Campaigns': Launches/events (e.g., "webinar," "launch").
      - 'Surveys': Feedback requests (e.g., "survey," "rate us").
      - 'Ads': General ads (e.g., "try," "subscribe").
    - 'General Inquiry': Doesn't fit elsewhere.
      - 'Personal': Non-work (e.g., "dinner," "plans").
      - 'Unsolicited': Cold emails (e.g., "found you online").
      - 'Info Requests': Generic questions (e.g., "hours?").
      - 'Miscellaneous': Uncategorized (e.g., "random").

        Additional rules:
            - If an email fits multiple categories, prioritize in this order:
            1. 'To Respond' ONLY if the email explicitly asks for YOUR direct response or action (with clear language like "please reply," "we need your input," "can you provide")
            2. 'Awaiting Reply' if it's a follow-up to a conversation YOU initiated
            3. 'Notification' if it's system-generated/automated (look for noreply@, system@, etc.)
            4. 'FYI' if it's human-written informational content
            5. The most specific remaining category-subcategory pair
            - Emails from 'donotreply' or 'noreply' default to 'Notification - Confirmations' unless they:
            - Require a response (then 'To Respond - Urgent')
            - Contain verification codes (then 'Notification - OTP')
            - Are subscription updates (then 'Notification - Subscriptions')
            - Default to 'General Inquiry - Miscellaneous' only if no clear fit exists after applying all rules

    Email text: {text}
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an email classifier. Respond with only the category-subcategory (e.g., 'B2B Query - Sales')."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=20,  # Increased slightly to fit longer category-subcategory names
            temperature=0.1  # Low temperature for deterministic responses
        )
        category = response.choices[0].message.content.strip()
        if category in categories:
            logging.debug(f"Email '{email['subject']}' classified as {category} by OpenAI")
            return category
        else:
            logging.warning(f"Unexpected OpenAI response: {category}. Defaulting to General Inquiry - Miscellaneous.")
            return "General Inquiry - Miscellaneous"
    except Exception as e:
        logging.error(f"Failed to classify email with OpenAI API: {e}")
        return "General Inquiry - Miscellaneous"

def sanitize_folder_name(folder_name: str) -> str:
    """Clean folder names for IMAP compatibility, preserving hierarchy."""
    return re.sub(r'[/]', '_', folder_name)  

def create_folder(mail: imaplib.IMAP4_SSL, folder_name: str) -> None:
    """Create an IMAP folder, handling nested structures and existing folders."""
    logging.info(f"Attempting to create folder: {folder_name}")
    
    try:
        status, folders = mail.list()
        folder_exists = any(folder_name.encode() in folder for folder in folders) if status == "OK" else False
        if not folder_exists:
            status, response = mail.create(folder_name)
            if status != "OK":
                logging.warning(f"Folder creation returned: {status} - {response}")
            else:
                logging.info(f"Folder '{folder_name}' created successfully.")
        else:
            logging.debug(f"Folder '{folder_name}' already exists.")
    except Exception as e:
        logging.error(f"Error in folder creation: {e}")

def get_separator(mail: imaplib.IMAP4_SSL) -> str:
    """Determine the IMAP folder separator for the server."""
    logging.debug("Determining IMAP folder separator...")
    try:
        status, folder_list = mail.list()
        if status == "OK":
            for folder in folder_list:
                if folder:
                    parts = folder.decode().split('"')
                    if len(parts) > 1:
                        return parts[1]
        logging.warning("Could not determine separator, using '/'")
    except Exception as e:
        logging.error(f"Error getting separator: {e}")
    return "/"

def save_emails_to_json(categorized_emails: Dict, file_name: str = "emails_by_category.json") -> None:
    """Save categorized emails to a JSON file efficiently."""
    logging.info(f"Saving categorized emails to JSON file: {file_name}")
    try:
        with open(file_name, 'w', encoding='utf-8') as json_file:
            json.dump({k: [{"subject": e["subject"]} for e in v] 
                      for k, v in categorized_emails.items()}, json_file, indent=4)
        logging.info(f"Emails successfully saved to {file_name}")
    except Exception as e:
        logging.error(f"Failed to save emails to JSON: {e}")

def create_all_category_folders(mail: imaplib.IMAP4_SSL) -> None:
    """Pre-create all category-subcategory folders as nested structures."""
    logging.info("Pre-creating all category-subcategory folders...")
    for category in CATEGORIES:
        # Split into main category and subcategory
        main_category, subcategory = category.split(" - ", 1)
        sanitized_main = sanitize_folder_name(main_category).replace(" ", "_")  # e.g., "Awaiting_Reply"
        sanitized_sub = sanitize_folder_name(subcategory).replace(" ", "_")     # e.g., "Delayed_Responses"
        full_folder_name = f"INBOX.{sanitized_main}.{sanitized_sub}"           # e.g., "INBOX.Awaiting_Reply.Delayed_Responses"
        try:
            # Create main folder first (e.g., "INBOX.Awaiting_Reply")
            main_folder = f"INBOX.{sanitized_main}"
            mail.create(main_folder)
            # Then create subfolder
            mail.create(full_folder_name)
            logging.info(f"Created category folder: {full_folder_name}")
        except imaplib.IMAP4.error as e:
            if 'ALREADYEXISTS' not in str(e):
                logging.warning(f"Error creating category folder {full_folder_name}: {e}")

def move_email_to_folder(mail: imaplib.IMAP4_SSL, email_id: str, category: str) -> bool:
    """Move an email to the specified category folder efficiently and mark it unseen."""
    logging.info(f"Moving email ID {email_id} to folder {category}")
    
    # Split category into main and subcategory
    try:
        main_category, subcategory = category.split(" - ", 1)
    except ValueError:
        main_category = category
        subcategory = None
    
    # Sanitize and construct folder name
    sanitized_main = sanitize_folder_name(main_category).replace(" ", "_")
    if subcategory:
        sanitized_sub = sanitize_folder_name(subcategory).replace(" ", "_")
        full_folder_name = f"INBOX.{sanitized_main}.{sanitized_sub}"
    else:
        full_folder_name = f"INBOX.{sanitized_main}"
    
    create_folder(mail, full_folder_name)
    
    try:
        # Ensure we're starting from INBOX
        mail.select("INBOX")
        
        # Try MOVE first
        try:
            status, data = mail.uid('MOVE', email_id, full_folder_name)
            if status == "OK":
                logging.info(f"Successfully moved email ID {email_id} to folder '{full_folder_name}'")
                # Select destination folder to set flags
                mail.select(full_folder_name)
                # Search for the email in the new folder to get its new UID
                status, msgnums = mail.uid('SEARCH', None, f'UID {email_id}')
                if status == "OK" and msgnums[0]:
                    new_uid = msgnums[0].decode().split()[-1]  # Get the last UID if multiple
                    mail.uid('STORE', new_uid, '-FLAGS', '(\\Seen)')
                    logging.info(f"Marked email ID {new_uid} as unseen in '{full_folder_name}'")
                # Return to INBOX
                mail.select("INBOX")
                return True
        except (imaplib.IMAP4.error, AttributeError) as e:
            logging.debug(f"MOVE command failed or not supported: {e}. Trying COPY+DELETE...")
        
        # Fallback to COPY + DELETE
        status, data = mail.uid('COPY', email_id, full_folder_name)
        if status == "OK":
            # Select destination folder to find the new UID
            mail.select(full_folder_name)
            # Search for the copied email (assuming it’s recent)
            status, msgnums = mail.uid('SEARCH', None, 'RECENT')
            if status == "OK" and msgnums[0]:
                new_uid = msgnums[0].decode().split()[-1]  # Assume last UID is the new one
                mail.uid('STORE', new_uid, '-FLAGS', '(\\Seen)')
                logging.info(f"Marked email ID {new_uid} as unseen in '{full_folder_name}'")
            
            # Return to INBOX and delete original
            mail.select("INBOX")
            mail.uid('STORE', email_id, '+FLAGS', '\\Deleted')
            mail.expunge()
            logging.info(f"Successfully copied and deleted email ID {email_id} to folder")
            return True
        logging.error(f"Failed to copy email ID {email_id}: {status}")
        return False
    except Exception as e:
        logging.error(f"Error moving email ID {email_id}: {e}")
        # Ensure we’re back in INBOX on failure
        mail.select("INBOX")
        return False

def extract_sender_info(msg: email.message.Message) -> dict:
    """Extract sender email and name from an email message."""
    sender = msg.get("from", "")
    if not sender:
        return {"email": "", "name": ""}
    match = re.search(r'<([^>]+)>', sender)
    if match:
        email = match.group(1).lower()
        name_part = sender.split('<')[0].strip()
        if name_part.endswith('"'):
            name_part = name_part.strip('"')
        return {"email": email, "name": name_part}
    return {"email": sender.lower(), "name": ""}

def read_and_process_email(mail: imaplib.IMAP4_SSL, email_id: str) -> Optional[dict]:
    """Fetch, process, categorize, and move a single email, including thread history."""
    global EMAIL_COUNT
    EMAIL_COUNT += 1
    logging.info(f"-----------------------------------------\n************** EMAIL COUNT {EMAIL_COUNT} *******\n-----------------------------------------")
    logging.info(f"Processing email ID: {email_id}")
    time.sleep(FETCH_DELAY)
    
    try:
        logging.debug(f"Attempting to fetch email ID {email_id} with BODY.PEEK")
        status, email_data = mail.uid('FETCH', email_id, "(BODY.PEEK[])")
        if status != "OK" or not email_data or not any(isinstance(part, tuple) for part in email_data):
            logging.warning(f"Failed to fetch email ID {email_id}: Status={status}, Data={email_data}")
            return None
        
        logging.debug(f"Email data fetched for ID {email_id}: {len(email_data)} parts")
        for response_part in email_data:
            if isinstance(response_part, tuple):
                raw_email = response_part[1]
                if not raw_email:
                    logging.warning(f"Empty raw email data for ID {email_id}")
                    return None
                logging.debug(f"Raw email size for ID {email_id}: {len(raw_email)} bytes")
                msg = message_from_bytes(raw_email)
                subject = decode_subject(msg["subject"]) if msg["subject"] else ""
                sender_info = extract_sender_info(msg)
                logging.info("BELOW IS THE EMAIL subject")
                logging.info(subject)
                
                # Extract body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition", ""))
                        if "attachment" in content_disposition:
                            continue
                        if content_type == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode("utf-8", errors='ignore')
                                break
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
                            body = payload.decode("latin-1", errors='ignore')
                        except:
                            body = ""
                
                if body and ("<html" in body.lower() or "<body" in body.lower()):
                    body = clean_html_body(body)
                
                logging.debug(f"Extracted body length for ID {email_id}: {len(body) if body else 0} characters")
                
                # Fetch thread history (replies) with safeguards
                message_id = msg.get("Message-ID", "").strip()
                references = msg.get("References", "").split() + [msg.get("In-Reply-To", "")]
                thread_history = [f"Original: Subject: {subject}, Body: {body}"]
                
                if message_id:
                    logging.debug(f"Searching thread history for Message-ID: {message_id}")
                    safe_message_id = message_id.replace('"', '').replace(' ', '')
                    search_criteria = f'(HEADER "In-Reply-To" "{safe_message_id}" OR HEADER "References" "{safe_message_id}")'
                    try:
                        status, reply_ids = mail.uid('SEARCH', None, search_criteria)
                        if status == "OK" and reply_ids[0]:
                            reply_id_list = reply_ids[0].split()
                            for reply_id in reply_id_list[:5]:
                                status, reply_data = mail.uid('FETCH', reply_id, "(BODY.PEEK[])")
                                if status == "OK":
                                    for reply_part in reply_data:
                                        if isinstance(reply_part, tuple):
                                            reply_msg = message_from_bytes(reply_part[1])
                                            reply_subject = decode_subject(reply_msg["subject"]) if reply_msg["subject"] else ""
                                            reply_body = ""
                                            if reply_msg.is_multipart():
                                                for part in reply_msg.walk():
                                                    if part.get_content_type() == "text/plain":
                                                        try:
                                                            reply_body = part.get_payload(decode=True).decode("utf-8", errors='ignore')
                                                        except UnicodeDecodeError:
                                                            reply_body = part.get_payload(decode=True).decode("latin-1", errors='ignore')
                                                        break
                                            else:
                                                try:
                                                    reply_body = reply_msg.get_payload(decode=True).decode("utf-8", errors='ignore')
                                                except UnicodeDecodeError:
                                                    reply_body = reply_msg.get_payload(decode=True).decode("latin-1", errors='ignore')
                                            thread_history.append(f"Reply: Subject: {reply_subject}, Body: {reply_body[:500]}")
                        else:
                            logging.debug(f"No replies found or search failed for Message-ID: {message_id}")
                    except imaplib.IMAP4.error as e:
                        logging.warning(f"Failed to fetch thread history for email ID {email_id}: {e}")
                
                full_text = "\n".join(thread_history)[:2000]
                logging.debug(f"Thread history length for ID {email_id}: {len(full_text)} characters")
                
                email_data = {
                    "subject": subject,
                    "body": full_text,
                    "timestamp": msg["date"] if msg["date"] else "",
                    "email_id": email_id.decode(),
                    "from": sender_info["email"],
                    "sender_name": sender_info["name"],
                    "to": msg.get("to", ""),
                    "cc": msg.get("cc", ""),
                    "has_attachments": any("attachment" in str(part.get("Content-Disposition", "")) for part in msg.walk())
                }
                
                logging.debug(f"Classifying email ID {email_id}")
                category = classify_email(email_data, CATEGORIES)
                email_data["category"] = category
                
                logging.debug(f"Moving email ID {email_id} to category: {category}")
                move_result = move_email_to_folder(mail, email_id, email_data["category"])
                if move_result:
                    logging.info(f"Email ID {email_id.decode()} classified as {email_data['category']} and moved successfully")
                else:
                    logging.warning(f"Failed to move Email ID {email_id.decode()}")
                
                return email_data
    except Exception as e:
        logging.error(f"Error processing email ID {email_id}: {e}")
        return None

def main() -> None:
    """Orchestrate the email organization process efficiently."""
    logging.info("Starting email organization process with OpenAI API and 5-second delays...")
    mail = None
    try:
        logging.info(MY_NAME)
        mail = create_connection()
        create_all_category_folders(mail)            
        mail.select("INBOX")
        
        # Dictionary to store categorized emails for JSON
        categorized_emails = {category: [] for category in CATEGORIES}
        processed_ids = set()  # Track processed email IDs
        
        while True:  # Keep checking inbox until empty
            status, email_ids = mail.uid('SEARCH', None, 'ALL')
            if status != "OK":
                logging.error(f"Failed to search emails: {email_ids}")
                break
            
            email_id_list = email_ids[0].split()
            if not email_id_list:
                logging.info("No emails found in INBOX or all emails processed.")
                break
            
            logging.info(f"Found {len(email_id_list)} emails in INBOX")
            
            processed_count, success_count = 0, 0
            for i in range(0, len(email_id_list), BATCH_SIZE):
                batch_ids = email_id_list[i:i + BATCH_SIZE]
                logging.info(f"Processing batch {i+1} to {min(i+BATCH_SIZE, len(email_id_list))} of {len(email_id_list)} emails")
                
                for email_id in batch_ids:
                    if email_id in processed_ids:
                        logging.debug(f"Skipping already processed email ID: {email_id}")
                        continue
                    
                    processed_count += 1
                    try:
                        email = read_and_process_email(mail, email_id)
                        if email:
                            success_count += 1
                            processed_ids.add(email_id)
                            categorized_emails[email["category"]].append(email)  # Add to JSON data
                            if processed_count % 10 == 0:
                                logging.info(f"Progress: Processed {processed_count} of {len(email_id_list)} emails. Success: {success_count}")
                    except Exception as e:
                        logging.error(f"Error processing email ID {email_id}: {e}")
                        continue
                
                time.sleep(1)  # Delay between batches
            
            # Save to JSON after each batch to avoid memory issues with large inboxes
            save_emails_to_json(categorized_emails)
            mail.expunge()  # Ensure deleted/moved emails are purged
            mail.select("INBOX")  # Refresh inbox state
        
        logging.info(f"Email organization process completed. Processed {processed_count} emails, {success_count} successfully categorized.")
        
    except Exception as e:
        logging.error(f"Error in main process: {e}")
    finally:
        if mail:
            logout(mail)

if __name__ == "__main__":
    main()