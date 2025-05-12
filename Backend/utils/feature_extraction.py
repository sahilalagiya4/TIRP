"""
Utility functions for extracting features from URLs
These functions help identify potentially malicious patterns in URLs.
"""

import re
from urllib.parse import urlparse

# Suspicious TLD list
SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.gq', '.ml', '.cf', '.tk', '.ga',
                   '.info', '.online', '.site', '.biz', '.stream', '.cc', '.pw']

# Common phishing keywords
PHISHING_KEYWORDS = [
    'login', 'secure', 'verify', 'update', 'account', 'password', 'confirm',
    'wallet', 'bank', 'support', 'alert', 'security', 'authenticate',
    'verification', 'signin', 'customer', 'access', 'billing', 'recover'
]


def extract_url_features(url):
    """
    Extract a comprehensive set of features from a URL for machine learning.

    Args:
        url (str): The URL to analyze

    Returns:
        dict: Dictionary containing extracted features
    """
    # Parse URL
    parsed = urlparse(url)

    # Basic features
    features = {
        'url_length': len(url),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'num_digits': sum(c.isdigit() for c in url),
        'num_letters': sum(c.isalpha() for c in url),
        'num_special': len(url) - sum(c.isdigit() for c in url) - sum(c.isalpha() for c in url),

        # Special character counts
        'dots': url.count('.'),
        'slashes': url.count('/'),
        'hyphens': url.count('-'),
        'underscores': url.count('_'),
        'equals': url.count('='),
        'ats': url.count('@'),
        'questions': url.count('?'),
        'ampersands': url.count('&'),
        'percents': url.count('%'),

        # Red flags
        'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        'suspicious_tld': int(any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        'has_phishing_keyword': int(any(kw in url.lower() for kw in PHISHING_KEYWORDS)),
        'excessive_subdomains': int(parsed.netloc.count('.') > 2),
        'url_contains_hex': int(bool(re.search(r'%[0-9a-fA-F]{2}', url))),
        'has_suspicious_character_mix': int(entropy_based_analysis(url) > 5)
    }

    return features


def extract_numeric_features(url):
    """
    Extract only the numeric features from a URL for the ML model.
    This is to maintain compatibility with the trained model.

    Args:
        url (str): The URL to analyze

    Returns:
        list: List of numerical features in the expected order
    """
    parsed = urlparse(url)

    features = [
        len(url),  # url_length
        len(parsed.netloc),  # domain_length
        len(parsed.path),  # path_length
        sum(c.isdigit() for c in url),  # num_digits
        sum(c.isalpha() for c in url),  # num_letters
        len(url) - sum(c.isdigit() for c in url) - sum(c.isalpha() for c in url),  # num_special
        url.count('.'),  # dots
        url.count('/'),  # slashes
        url.count('-'),  # hyphens
        url.count('_'),  # underscores
        url.count('='),  # equals
        url.count('@'),  # ats
        url.count('?'),  # questions
        url.count('&'),  # ampersands
        url.count('%'),  # percents
        int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),  # has_ip
        int(any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS))  # suspicious_tld
    ]

    return features


def entropy_based_analysis(url):
    """
    Performs entropy-based analysis on the URL to detect unusual character patterns.
    Higher score means more suspicious (range 0-10).

    Args:
        url (str): The URL to analyze

    Returns:
        float: Suspicion score based on character patterns
    """
    # Count transitions between different character types
    transitions = 0
    prev_type = None

    for c in url:
        if c.isdigit():
            curr_type = 'digit'
        elif c.isalpha():
            curr_type = 'alpha'
        else:
            curr_type = 'special'

        if prev_type and prev_type != curr_type:
            transitions += 1

        prev_type = curr_type

    # Calculate normalized score
    url_length = max(len(url), 1)  # Avoid division by zero
    transition_ratio = transitions / url_length

    # More transitions means more mixed character types, which can be suspicious
    # Normal URLs have a transition ratio around 0.2-0.3
    # Highly suspicious URLs often have ratios > 0.4
    if transition_ratio > 0.4:
        score = min(10, transition_ratio * 20)
    else:
        score = transition_ratio * 10

    return score


def get_domain_age_category(domain_age_days):
    """
    Categorize domain age into risk levels.

    Args:
        domain_age_days (int): Age of domain in days

    Returns:
        str: Risk category based on domain age
    """
    if domain_age_days < 30:
        return "very_high_risk"  # Very new domains are highly suspicious
    elif domain_age_days < 90:
        return "high_risk"
    elif domain_age_days < 180:
        return "medium_risk"
    elif domain_age_days < 365:
        return "low_risk"
    else:
        return "very_low_risk"  # Established domains are less likely to be malicious