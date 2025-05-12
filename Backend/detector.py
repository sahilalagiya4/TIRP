import tensorflow as tf
import numpy as np
import pickle
import re
from urllib.parse import urlparse
import os
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, LSTM, Dense, Dropout, Conv1D, MaxPooling1D, Concatenate, GlobalMaxPooling1D, Bidirectional
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Constants
MAX_URL_LENGTH = 200
MAX_VOCAB_SIZE = 10000
EMBEDDING_DIM = 100
LSTM_UNITS = 128
CNN_FILTERS = 256
DROPOUT_RATE = 0.3
BATCH_SIZE = 32
EPOCHS = 15
TEST_SIZE = 0.2
VALIDATION_SIZE = 0.1

class URLMalwareDetector:
    def __init__(self, model_path=None, word_tokenizer_path=None, char_tokenizer_path=None):
        self.model_dir = 'models'
        self.model_path = model_path or os.path.join(self.model_dir, 'url_malware_model_latest.h5')
        self.word_tokenizer_path = word_tokenizer_path or os.path.join(self.model_dir, 'url_tokenizer.pickle')
        self.char_tokenizer_path = char_tokenizer_path or os.path.join(self.model_dir, 'url_char_tokenizer.pickle')
        os.makedirs(self.model_dir, exist_ok=True)

        self.model_loaded = os.path.exists(self.model_path)
        self.tokenizers_loaded = os.path.exists(self.word_tokenizer_path) and os.path.exists(self.char_tokenizer_path)

        if self.model_loaded:
            try:
                self.model = tf.keras.models.load_model(self.model_path)
                print(f"✅ Model loaded from {self.model_path}")
            except Exception as e:
                print(f"❌ Error loading model: {e}")
                self.model_loaded = False

        if self.tokenizers_loaded:
            try:
                with open(self.word_tokenizer_path, 'rb') as handle:
                    self.word_tokenizer = pickle.load(handle)
                with open(self.char_tokenizer_path, 'rb') as handle:
                    self.char_tokenizer = pickle.load(handle)
                print(f"✅ Tokenizers loaded")
            except Exception as e:
                print(f"❌ Error loading tokenizers: {e}")
                self.tokenizers_loaded = False

        self.malware_types = ['Phishing', 'Trojan', 'Adware', 'Spyware', 'Ransomware', 'Cryptojacking', 'Scam', 'Suspicious', 'Malware', 'None']

    def extract_features(self, url):
        parsed_url = urlparse(url)
        features = {
            'url_length': len(url),
            'domain_length': len(parsed_url.netloc),
            'path_length': len(parsed_url.path),
            'num_digits': sum(c.isdigit() for c in url),
            'num_letters': sum(c.isalpha() for c in url),
            'num_special': len(url) - sum(c.isdigit() for c in url) - sum(c.isalpha() for c in url),
            'dots': url.count('.'),
            'slashes': url.count('/'),
            'hyphens': url.count('-'),
            'underscores': url.count('_'),
            'equals': url.count('='),
            'ats': url.count('@'),
            'questions': url.count('?'),
            'ampersands': url.count('&'),
            'percents': url.count('%'),
            'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
            'suspicious_tld': int(any(parsed_url.netloc.endswith(tld) for tld in ['.xyz', '.top', '.club', '.gq', '.ml', '.cf', '.tk', '.ga']))
        }
        return list(features.values())

    def preprocess_url(self, url):
        if not self.tokenizers_loaded:
            manual_features = np.array([self.extract_features(url)])
            return [None, None, manual_features]
        word_seq = self.word_tokenizer.texts_to_sequences([url])
        word_padded = pad_sequences(word_seq, maxlen=MAX_URL_LENGTH)
        char_seq = self.char_tokenizer.texts_to_sequences([url])
        char_padded = pad_sequences(char_seq, maxlen=MAX_URL_LENGTH * 2)
        manual_features = np.array([self.extract_features(url)])
        return [word_padded, char_padded, manual_features]

    def predict(self, url):
        if not self.model_loaded or not self.tokenizers_loaded:
            return self.rule_based_detection(url)
        model_input = self.preprocess_url(url)
        try:
            outputs = self.model.predict(model_input)
            if isinstance(outputs, list):
                binary_pred = outputs[0][0][0]
                is_malicious = binary_pred > 0.5
                confidence = float(binary_pred) if is_malicious else 1 - float(binary_pred)
                type_pred = outputs[1][0]
                malware_probs = {malware_type: float(prob) * 100 for malware_type, prob in zip(self.malware_types, type_pred)}
                malware_probs_sorted = dict(sorted(malware_probs.items(), key=lambda item: item[1], reverse=True))
            else:
                binary_pred = outputs[0][0]
                is_malicious = binary_pred > 0.5
                confidence = float(binary_pred) if is_malicious else 1 - float(binary_pred)
                malware_probs_sorted = {}
            risk_score = int(confidence * 100) if is_malicious else int((1 - confidence) * 100)
            result = {
                'url': url,
                'is_malicious': bool(is_malicious),
                'confidence': float(confidence),
                'risk_score': risk_score,
                'malware_probabilities': malware_probs_sorted
            }
            if is_malicious:
                result['details'] = {k: self.get_malware_details(k) for k in malware_probs_sorted}
            return result
        except Exception as e:
            print(f"Error during prediction: {e}")
            return self.rule_based_detection(url)

    def rule_based_detection(self, url):
        features = self.extract_features(url)
        parsed_url = urlparse(url)
        has_ip = bool(features[15])
        has_suspicious_tld = bool(features[16])
        excessive_dots = features[6] > 5
        excessive_specials = features[4] / (len(url) + 0.01) > 0.3
        has_suspicious_keywords = any(kw in url.lower() for kw in ['login', 'secure', 'verify', 'update', 'account', 'password', 'confirm', 'wallet', 'bank', 'support', 'alert', 'security'])
        risk_factors = [has_ip * 20, has_suspicious_tld * 15, excessive_dots * 10, excessive_specials * 15, has_suspicious_keywords * 10]
        risk_score = min(sum(risk_factors), 100)
        is_malicious = risk_score > 50
        malware_type = None
        if is_malicious:
            if any(kw in url.lower() for kw in ['login', 'password', 'account', 'bank', 'verify']):
                malware_type = 'Phishing'
            elif '.exe' in url.lower() or 'download' in url.lower():
                malware_type = 'Trojan'
            elif 'crypto' in url.lower() or 'bitcoin' in url.lower() or 'mining' in url.lower():
                malware_type = 'Cryptojacking'
            elif 'prize' in url.lower() or 'win' in url.lower() or 'claim' in url.lower():
                malware_type = 'Scam'
            else:
                malware_type = 'Suspicious'
        result = {
            'url': url,
            'is_malicious': is_malicious,
            'confidence': risk_score / 100.0,
            'risk_score': risk_score
        }
        if is_malicious and malware_type:
            result['malware_type'] = malware_type
            result['details'] = self.get_malware_details(malware_type)
        return result

    def get_malware_details(self, malware_type):
        details_map = {
            'Phishing': "Phishing attempt.",
            'Trojan': "Trojan horse.",
            'Adware': "Unwanted ads.",
            'Spyware': "Monitors activities.",
            'Ransomware': "Encrypts files for ransom.",
            'Cryptojacking': "Mining cryptocurrency without consent.",
            'Scam': "Fraudulent activity.",
            'Suspicious': "Suspicious behavior.",
            'Malware': "General malware."
        }
        return details_map.get(malware_type, "Potentially malicious.")

    def demo(self):
        test_urls = [
            "http://microphone-recorder-stealth.xyz/install.exe",
            "http://screenpresso-pro-cracked.xyz/install",
            "http://linkedln-support.com/confirm",
            "http://secure-appleid-login.com/authenticate",
            "http://drive-google-com.fanalav.com/6a7ec96d6a4b8b887e9f9ace81b40a99/"
        ]
        results = []
        for url in test_urls:
            result = self.predict(url)
            results.append(result)
            print(f"\nURL: {result['url']}")
            print(f"Is Malicious: {'Yes' if result['is_malicious'] else 'No'}")
            print(f"Confidence: {result['confidence'] * 100:.2f}%")
            if result['is_malicious']:
                print("Malware Type Probabilities:")
                for malware_type, percentage in result['malware_probabilities'].items():
                    print(f"  {malware_type}: {percentage:.2f}%")
        return results
