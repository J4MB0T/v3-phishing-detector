import os
import json
import re
from email import policy
from email.parser import BytesParser

def extract_body(msg):
    """Extract plain and HTML body from the email message."""
    body = {'text': '', 'html': ''}
    if msg.is_multipart():
        for part in msg.iter_parts():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))
            if 'attachment' not in content_disposition:
                if content_type == 'text/plain':
                    body['text'] = part.get_payload(decode=True).decode(part.get_content_charset(), 'ignore')
                elif content_type == 'text/html':
                    body['html'] = part.get_payload(decode=True).decode(part.get_content_charset(), 'ignore')
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            body['text'] = msg.get_payload(decode=True).decode(msg.get_content_charset(), 'ignore')
        elif content_type == 'text/html':
            body['html'] = msg.get_payload(decode=True).decode(msg.get_content_charset(), 'ignore')
    return body

def extract_attachments(msg):
    """Extract attachments from the email message."""
    attachments = []
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_disposition() == 'attachment':
                attachments.append({
                    'filename': part.get_filename(),
                    'type': part.get_content_type(),
                    'size': len(part.get_payload(decode=True))  # Get the size of the attachment
                })
    return attachments

def extract_urls(msg):
    """Extract URLs from the email body."""
    urls = set()
    body = extract_body(msg)
    text = body['text'] + body['html']
    urls.update(re.findall(r'http[s]?://\S+', text))
    return list(urls)

def parse_recipients(recipients):
    """Parse and return a list of recipient email addresses."""
    return [recipient.strip() for recipient in recipients]

def extract_headers(msg):
    """Extract all headers from the email message."""
    headers = {}
    for key, value in msg.items():
        headers[key] = value
    return headers

def convert_eml_to_json(eml_file_path, output_json_dir):
    """Convert an EML file to JSON and save it."""
    
    # Parse the EML file
    try:
        with open(eml_file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Extract the necessary fields from the email
        email_data = {
            "from": msg.get('From'),
            "to": parse_recipients(msg.get_all('To', [])),
            "cc": parse_recipients(msg.get_all('Cc', [])),
            "bcc": parse_recipients(msg.get_all('Bcc', [])),
            "subject": msg.get('Subject'),
            "date": msg.get('Date'),
            "body": extract_body(msg),
            "attachments": extract_attachments(msg),
            "urls": extract_urls(msg),
            "message_id": msg.get('Message-ID'),
            "in_reply_to": msg.get('In-Reply-To'),
            "references": msg.get_all('References', []),
            "received": msg.get_all('Received', []),
            "authentication_results": msg.get('Authentication-Results'),
            "received_spf": msg.get('Received-SPF'),
            "dkim_signature": msg.get('DKIM-Signature'),
            "list_unsubscribe": msg.get('List-Unsubscribe'),
            "headers": extract_headers(msg)  # Include headers in the JSON output
        }

        # Define the JSON filename (based on the message_id or subject)
        subject = email_data['subject'] if email_data['subject'] else "no_subject"
        clean_subject = re.sub(r'[^a-zA-Z0-9]+', '_', subject)
        json_filename = os.path.join(output_json_dir, f"{clean_subject}.json")

        # Save the email data as JSON
        with open(json_filename, 'w') as json_file:
            json.dump(email_data, json_file, indent=4)

        print(f"JSON file saved as {json_filename}")
        return json_filename

    except Exception as e:
        print(f"Error: {str(e)}")

def process_eml_files(eml_folder, output_json_folder):
    """Process all .eml files in the specified folder and convert them to JSON."""
    
    # Ensure the output JSON folder exists
    os.makedirs(output_json_folder, exist_ok=True)

    # Get all the .eml files from the folder
    eml_files = [f for f in os.listdir(eml_folder) if f.endswith('.eml')]

    if not eml_files:
        print("No .eml files found to process.")
        return

    # Process each .eml file
    for eml_file in eml_files:
        eml_file_path = os.path.join(eml_folder, eml_file)
        print(f"Processing {eml_file_path}...")
        convert_eml_to_json(eml_file_path, output_json_folder)

if __name__ == "__main__":
    # Define the input and output folders
    eml_folder = "email_jsons"  # Folder where the .eml files are stored
    output_json_folder = "json"  # Folder where the .json files will be saved

    # Process all .eml files in the folder
    process_eml_files(eml_folder, output_json_folder)
