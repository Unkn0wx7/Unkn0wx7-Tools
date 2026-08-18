"""
Phishing Detection System with Analysis
Made By Unkn0wx7

A comprehensive phishing detection system that uses machine learning
and URL/email analysis to identify phishing attempts.
"""

import re
import urllib.parse
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle
import os


class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    @staticmethod
    def extract_features(url):
        """Extract relevant features from a URL"""
        features = {}
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Basic features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['subdomain_count'] = domain.count('.')
            
            # Special characters
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_double_slash'] = 1 if '//' in url[8:] else 0
            features['has_hyphen'] = 1 if '-' in domain else 0
            features['has_underscore'] = 1 if '_' in url else 0
            features['has_question_mark'] = 1 if '?' in url else 0
            
            # Protocol checks
            features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
            features['uses_http'] = 1 if parsed_url.scheme == 'http' else 0
            
            # Domain features
            features['is_ip_address'] = URLFeatureExtractor.is_ip_address(domain)
            features['domain_has_digits'] = 1 if any(char.isdigit() for char in domain) else 0
            
            # Port features
            features['uses_unusual_port'] = 1 if ':' in domain else 0
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return None
    
    @staticmethod
    def is_ip_address(domain):
        """Check if domain is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return 1 if re.match(ip_pattern, domain) else 0
    
    @staticmethod
    def has_suspicious_keywords(url):
        """Check for suspicious keywords in URL"""
        suspicious_keywords = [
            'verify', 'confirm', 'update', 'login', 'secure', 'account',
            'suspend', 'urgent', 'warning', 'action', 'click', 'alert'
        ]
        url_lower = url.lower()
        return sum(1 for keyword in suspicious_keywords if keyword in url_lower)


class EmailAnalyzer:
    """Analyze email headers and content for phishing indicators"""
    
    @staticmethod
    def analyze_sender(sender_email):
        """Analyze sender email address"""
        analysis = {
            'sender': sender_email,
            'is_suspicious': False,
            'reasons': []
        }
        
        # Check for spoofed domains
        if sender_email.count('@') != 1:
            analysis['is_suspicious'] = True
            analysis['reasons'].append("Invalid email format")
        
        domain = sender_email.split('@')[1].lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'.*\..*\..*@',  # Multiple dots before @
            r'.*no-?reply.*',  # No-reply addresses
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, sender_email):
                analysis['is_suspicious'] = True
                analysis['reasons'].append(f"Matches suspicious pattern: {pattern}")
        
        return analysis
    
    @staticmethod
    def analyze_content(email_content):
        """Analyze email content for phishing indicators"""
        analysis = {
            'suspicious_count': 0,
            'indicators': []
        }
        
        phishing_keywords = [
            'verify your account', 'confirm your identity', 'update payment',
            'urgent action required', 'click here immediately', 'unusual activity',
            'suspend', 'limited time', 'act now', 'unauthorized access'
        ]
        
        content_lower = email_content.lower()
        for keyword in phishing_keywords:
            if keyword in content_lower:
                analysis['suspicious_count'] += 1
                analysis['indicators'].append(keyword)
        
        # Check for urgency language
        urgency_words = ['urgent', 'immediately', 'quickly', 'now', 'asap']
        urgency_count = sum(1 for word in urgency_words if word in content_lower)
        if urgency_count >= 2:
            analysis['high_urgency'] = True
        
        return analysis


class PhishingDetector:
    """Main phishing detection system"""
    
    def __init__(self, model_path=None):
        """Initialize the detector with optional pre-trained model"""
        self.model = None
        self.feature_names = [
            'url_length', 'domain_length', 'path_length', 'subdomain_count',
            'has_at_symbol', 'has_double_slash', 'has_hyphen', 'has_underscore',
            'has_question_mark', 'uses_https', 'uses_http', 'is_ip_address',
            'domain_has_digits', 'uses_unusual_port', 'suspicious_keywords'
        ]
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self.train_default_model()
    
    def train_default_model(self):
        """Train a default model with sample data"""
        # Sample training data (simplified)
        X_train = np.array([
            [24, 8, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],  # Legitimate
            [45, 15, 8, 3, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 2],  # Suspicious
            [30, 10, 5, 2, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1],  # Phishing
        ])
        
        y_train = np.array([0, 1, 1])  # 0: Legitimate, 1: Phishing
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
    
    def detect(self, url, detailed=False):
        """
        Detect if a URL is phishing
        
        Args:
            url: URL to analyze
            detailed: Return detailed analysis
            
        Returns:
            Dictionary with detection results
        """
        result = {
            'url': url,
            'is_phishing': False,
            'confidence': 0.0,
            'risk_score': 0.0,
            'analysis': {}
        }
        
        try:
            # Extract features
            features = URLFeatureExtractor.extract_features(url)
            if not features:
                result['error'] = "Could not extract features"
                return result
            
            # Add suspicious keywords count
            features['suspicious_keywords'] = URLFeatureExtractor.has_suspicious_keywords(url)
            
            # Convert to array in correct order
            feature_array = np.array([
                [features[name] for name in self.feature_names]
            ])
            
            # Make prediction
            if self.model:
                prediction = self.model.predict(feature_array)[0]
                probability = self.model.predict_proba(feature_array)[0]
                
                result['is_phishing'] = bool(prediction)
                result['confidence'] = float(probability[prediction])
                result['risk_score'] = float(probability[1]) * 100
            
            if detailed:
                result['features'] = features
                result['analysis'] = self._detailed_analysis(url, features)
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def _detailed_analysis(self, url, features):
        """Perform detailed analysis of URL"""
        analysis = {
            'url_characteristics': {},
            'risk_indicators': [],
            'security_checks': {}
        }
        
        # URL Characteristics
        analysis['url_characteristics']['length'] = features['url_length']
        analysis['url_characteristics']['domain_length'] = features['domain_length']
        analysis['url_characteristics']['subdomain_count'] = features['subdomain_count']
        
        # Risk Indicators
        if features['is_ip_address']:
            analysis['risk_indicators'].append("Uses IP address instead of domain")
        if features['has_at_symbol']:
            analysis['risk_indicators'].append("Contains @ symbol (obfuscation technique)")
        if features['has_double_slash']:
            analysis['risk_indicators'].append("Double slash after domain (obfuscation)")
        if features['has_hyphen'] and features['subdomain_count'] > 2:
            analysis['risk_indicators'].append("Suspicious domain structure with hyphens")
        if not features['uses_https']:
            analysis['risk_indicators'].append("Does not use HTTPS")
        
        # Security Checks
        analysis['security_checks']['https_enabled'] = bool(features['uses_https'])
        analysis['security_checks']['suspicious_keywords_found'] = features['suspicious_keywords'] > 0
        
        return analysis
    
    def save_model(self, path):
        """Save trained model to file"""
        if self.model:
            with open(path, 'wb') as f:
                pickle.dump(self.model, f)
    
    def load_model(self, path):
        """Load trained model from file"""
        with open(path, 'rb') as f:
            self.model = pickle.load(f)


class PhishingAnalysisReport:
    """Generate comprehensive phishing analysis reports"""
    
    def __init__(self, detector):
        """Initialize report generator"""
        self.detector = detector
        self.report_data = {}
    
    def analyze_url(self, url):
        """Analyze a single URL and generate report"""
        detection_result = self.detector.detect(url, detailed=True)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'detection': detection_result,
            'summary': self._generate_summary(detection_result)
        }
        
        return report
    
    def analyze_batch(self, urls):
        """Analyze multiple URLs and generate batch report"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_urls': len(urls),
            'analyses': [],
            'summary': {}
        }
        
        phishing_count = 0
        total_risk = 0
        
        for url in urls:
            analysis = self.analyze_url(url)
            results['analyses'].append(analysis)
            
            if analysis['detection']['is_phishing']:
                phishing_count += 1
            total_risk += analysis['detection']['risk_score']
        
        results['summary'] = {
            'phishing_detected': phishing_count,
            'phishing_percentage': (phishing_count / len(urls) * 100) if urls else 0,
            'average_risk_score': total_risk / len(urls) if urls else 0
        }
        
        return results
    
    def _generate_summary(self, detection_result):
        """Generate summary for a detection result"""
        risk_score = detection_result['risk_score']
        
        if risk_score >= 80:
            threat_level = "CRITICAL"
        elif risk_score >= 60:
            threat_level = "HIGH"
        elif risk_score >= 40:
            threat_level = "MEDIUM"
        elif risk_score >= 20:
            threat_level = "LOW"
        else:
            threat_level = "MINIMAL"
        
        return {
            'is_phishing': detection_result['is_phishing'],
            'threat_level': threat_level,
            'risk_score': detection_result['risk_score'],
            'confidence': detection_result['confidence'],
            'recommendation': self._get_recommendation(threat_level)
        }
    
    def _get_recommendation(self, threat_level):
        """Get security recommendation based on threat level"""
        recommendations = {
            'CRITICAL': 'Block this URL immediately. Do not click or interact with it.',
            'HIGH': 'Avoid this URL. Mark as spam/phishing if received in email.',
            'MEDIUM': 'Exercise caution. Verify URL authenticity before interaction.',
            'LOW': 'Likely safe but maintain standard security practices.',
            'MINIMAL': 'URL appears to be legitimate.'
        }
        return recommendations.get(threat_level, 'Unknown threat level')
    
    def export_report(self, report, format='json'):
        """Export report in specified format"""
        if format == 'json':
            import json
            return json.dumps(report, indent=2)
        elif format == 'text':
            return self._format_text_report(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_text_report(self, report):
        """Format report as text"""
        text = f"""
{'='*60}
PHISHING DETECTION ANALYSIS REPORT
Made By Unkn0wx7
{'='*60}

Report Generated: {report['timestamp']}
URL Analyzed: {report['url']}

DETECTION RESULTS:
-----------------
Is Phishing: {report['detection']['is_phishing']}
Risk Score: {report['detection']['risk_score']:.2f}%
Confidence: {report['detection']['confidence']:.2f}%

THREAT ASSESSMENT:
------------------
Threat Level: {report['summary']['threat_level']}
Recommendation: {report['summary']['recommendation']}

{'='*60}
"""
        return text


# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = PhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://g00gle-secure-verify.com/login",
        "https://192.168.1.1/admin@bank.com/verify",
        "https://github.com/Unkn0wx7",
    ]
    
    # Create analysis report generator
    report_gen = PhishingAnalysisReport(detector)
    
    # Analyze batch
    batch_report = report_gen.analyze_batch(test_urls)
    
    # Print results
    print(report_gen.export_report(batch_report, format='text'))
    
    # Analyze individual URL with detailed analysis
    detailed_report = report_gen.analyze_url(test_urls[1])
    print("\nDetailed Analysis:")
    print(report_gen.export_report(detailed_report, format='text'))
