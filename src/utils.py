"""
Utility functions for subdomain discovery
Adapted from CloudSight utilities
"""
import re
import tldextract
import validators
from urllib.parse import urlparse
from typing import Optional

def validate_domain(domain: str) -> bool:
    """Validate if a string is a valid domain name"""
    if not domain:
        return False
    
    # Use validators library for basic validation
    if not validators.domain(domain):
        return False
    
    # Additional checks
    if len(domain) > 253:  # Maximum domain length
        return False
    
    if '..' in domain:  # No consecutive dots
        return False
    
    if domain.startswith('.') or domain.endswith('.'):  # No leading/trailing dots
        return False
    
    return True

def normalize_domain(domain_input: str) -> str:
    """Normalize domain input (adapted from CloudSight's get_domain_from_input)"""
    if not domain_input:
        return ""
    
    # Strip whitespace
    domain_input = domain_input.strip()
    
    # Remove protocol if present
    if '://' in domain_input:
        parsed = urlparse(domain_input)
        domain = parsed.netloc if parsed.netloc else ""
    else:
        # Handle cases with paths or ports
        if '/' in domain_input:
            # Split on first slash to remove path
            domain = domain_input.split('/')[0]
        else:
            domain = domain_input
    
    # Remove port if present (but not for IPv6)
    if ':' in domain and not domain.count(':') > 1:  # Not IPv6
        domain = domain.split(':')[0]
    
    # Remove trailing dot
    domain = domain.rstrip('.')
    
    # Convert to lowercase
    domain = domain.lower()
    
    # Additional cleanup
    domain = domain.strip()
    
    return domain

def is_valid_subdomain(subdomain: str) -> bool:
    """Check if a subdomain is valid and not obviously fake"""
    if not subdomain:
        return False
    
    # Basic validation
    if not validate_domain(subdomain):
        return False
    
    # Check for reasonable length
    if len(subdomain) > 253:
        return False
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'[a-f0-9]{32}',  # MD5 hashes
        r'[a-f0-9]{64}',  # SHA256 hashes
        r'(.)\1{10,}',    # Repeated characters
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, subdomain):
            return False
    
    return True

def extract_root_domain(domain: str) -> str:
    """Extract root domain from subdomain"""
    try:
        extracted = tldextract.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        return domain

def is_subdomain_of(subdomain: str, root_domain: str) -> bool:
    """Check if subdomain belongs to root domain"""
    if not subdomain or not root_domain:
        return False
    
    subdomain = subdomain.lower().rstrip('.')
    root_domain = root_domain.lower().rstrip('.')
    
    if subdomain == root_domain:
        return True
    
    return subdomain.endswith(f".{root_domain}")

def sanitize_domain_for_filename(domain: str) -> str:
    """Sanitize domain name for use in filenames"""
    # Replace invalid filename characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', domain)
    
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    
    return sanitized

def get_subdomain_depth(subdomain: str) -> int:
    """Get the depth of a subdomain (number of dots)"""
    return subdomain.count('.')

def classify_subdomain_type(subdomain: str) -> str:
    """Classify subdomain based on common patterns"""
    subdomain_lower = subdomain.lower()
    
    # Extract the subdomain part (everything before the root domain)
    parts = subdomain_lower.split('.')
    if len(parts) < 2:
        return "unknown"
    
    subdomain_part = parts[0]
    
    # Classification based on common patterns
    if subdomain_part in ['www', 'www2', 'www3']:
        return "web"
    elif subdomain_part in ['api', 'rest', 'graphql', 'v1', 'v2']:
        return "api"
    elif subdomain_part in ['admin', 'administrator', 'manage', 'control']:
        return "admin"
    elif subdomain_part in ['dev', 'develop', 'development', 'test', 'testing', 'stage', 'staging']:
        return "development"
    elif subdomain_part in ['mail', 'email', 'smtp', 'imap', 'pop', 'webmail']:
        return "email"
    elif subdomain_part in ['ftp', 'sftp', 'files', 'upload', 'download']:
        return "file_transfer"
    elif subdomain_part in ['db', 'database', 'mysql', 'postgres', 'mongo']:
        return "database"
    elif subdomain_part in ['cdn', 'static', 'assets', 'media', 'images']:
        return "content_delivery"
    elif subdomain_part in ['blog', 'news', 'forum', 'community']:
        return "content"
    elif subdomain_part in ['shop', 'store', 'ecommerce', 'cart', 'checkout']:
        return "ecommerce"
    elif subdomain_part in ['support', 'help', 'docs', 'documentation']:
        return "support"
    elif subdomain_part in ['monitoring', 'metrics', 'status', 'health']:
        return "monitoring"
    elif subdomain_part in ['vpn', 'proxy', 'gateway', 'firewall']:
        return "network"
    elif re.match(r'^[a-z]{2}$', subdomain_part):  # Two letter codes
        return "localization"
    elif re.match(r'^\d+$', subdomain_part):  # Pure numbers
        return "numeric"
    else:
        return "other"

def is_wildcard_domain(domain: str) -> bool:
    """Check if domain uses wildcard DNS"""
    try:
        import dns.resolver
        
        # Try to resolve a random subdomain
        random_subdomain = f"nonexistent-random-{hash(domain) % 10000}.{domain}"
        
        try:
            dns.resolver.resolve(random_subdomain, 'A')
            return True  # If it resolves, it's likely a wildcard
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False  # Normal behavior
        except Exception:
            return False  # Assume no wildcard on other errors
    
    except ImportError:
        return False  # Can't check without dnspython