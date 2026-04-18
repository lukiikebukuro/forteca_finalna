"""
RODO/GDPR Compliance Functions
IP hashing, masking, PII scrubbing, session cleanup, DNT check
"""
import hashlib
import re
from datetime import datetime, timedelta
import sqlite3

from config import app, DATABASE_NAME


def hash_ip_address(ip):
    """RODO: Hash IP address using SHA-256, return truncated 16-char hash"""
    if not ip:
        return 'hash_unknown'
    try:
        hash_object = hashlib.sha256(ip.encode('utf-8'))
        return f'hash_{hash_object.hexdigest()[:16]}'
    except Exception as e:
        print(f"[ERROR] IP hashing failed: {e}")
        app.logger.error(f"IP hashing failed: {e}")
        return 'hash_error'


def mask_ip_address(ip):
    """RODO: Mask last octet of IPv4 or tail of IPv6"""
    if not ip:
        return 'masked'
    try:
        if '.' in ip and ip.count('.') == 3:
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        elif ':' in ip:
            parts = ip.split(':')
            return ':'.join(parts[:-2]) + '::xxxx'
        return 'masked'
    except Exception as e:
        print(f"[ERROR] IP masking failed: {e}")
        app.logger.error(f"IP masking failed: {e}")
        return 'masked'


def scrub_pii(text):
    """
    RODO: Sanitize PII data
    Removes: Email, Phone, PESEL, Credit Cards, IBAN, NIP
    """
    if not text or not isinstance(text, str):
        return text

    scrubbed = text
    pii_detected = False

    # Email
    original = scrubbed
    scrubbed = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        '[REDACTED_EMAIL]', scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: Email address scrubbed")

    # Polish phone: +48 123 456 789
    original = scrubbed
    scrubbed = re.sub(
        r'(\+48\s?)?(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})',
        '[REDACTED_PHONE]', scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: Phone number scrubbed")

    # PESEL: 11 digits
    original = scrubbed
    scrubbed = re.sub(r'\b\d{11}\b', '[REDACTED_PESEL]', scrubbed)
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: PESEL scrubbed")

    # Credit card: 16 digits
    original = scrubbed
    scrubbed = re.sub(
        r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        '[REDACTED_CARD]', scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: Credit card scrubbed")

    # IBAN: PL + 26 digits
    original = scrubbed
    scrubbed = re.sub(r'\bPL\d{26}\b', '[REDACTED_IBAN]', scrubbed, flags=re.IGNORECASE)
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: IBAN scrubbed")

    # NIP: 10 digits with optional dashes
    original = scrubbed
    scrubbed = re.sub(
        r'\b\d{3}[\-]?\d{3}[\-]?\d{2}[\-]?\d{2}\b',
        '[REDACTED_NIP]', scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: NIP scrubbed")

    if pii_detected:
        print(f"[RODO WARNING] PII detected and scrubbed - original length: {len(text)}, scrubbed: {len(scrubbed)}")

    return scrubbed


def cleanup_old_sessions():
    """RODO: Delete visitor sessions older than 30 days"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=30)).isoformat()
        cursor.execute('DELETE FROM visitor_sessions WHERE entry_time < ?', (cutoff_date,))
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted_count > 0:
            print(f"[RODO CLEANUP] Removed {deleted_count} sessions older than 30 days")
            app.logger.info(f"RODO cleanup: Removed {deleted_count} old sessions")
        return deleted_count
    except Exception as e:
        print(f"[ERROR] Session cleanup failed: {e}")
        app.logger.error(f"Session cleanup failed: {e}", exc_info=True)
        return 0


def check_do_not_track(request):
    """RODO: Check if user has Do Not Track enabled"""
    dnt_header = request.headers.get('DNT') or request.headers.get('dnt')
    return dnt_header == '1'
