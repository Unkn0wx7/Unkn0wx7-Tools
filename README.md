# Unkn0wx7 Tools

**Made By Unkn0wx7**

A collection of powerful security and utility tools for cybersecurity professionals and developers.

## Tools Included

### 1. Phishing Detection System
A comprehensive machine learning-based phishing detection system with advanced analysis capabilities.

#### Features:
- **URL Feature Extraction**: Analyzes URLs for suspicious patterns and characteristics
- **Machine Learning Detection**: Uses Random Forest classifier for accurate phishing detection
- **Email Analysis**: Analyzes sender addresses and email content for phishing indicators
- **Comprehensive Reporting**: Generates detailed analysis reports with threat levels
- **Batch Analysis**: Process multiple URLs simultaneously
- **Risk Scoring**: Calculates risk scores from 0-100%

#### Key Components:
- `URLFeatureExtractor`: Extracts 15+ features from URLs
- `EmailAnalyzer`: Analyzes email headers and content
- `PhishingDetector`: Main detection engine with ML model
- `PhishingAnalysisReport`: Report generation and formatting

#### Installation:
```bash
pip install numpy scikit-learn
```

#### Usage:
```python
from phishing_detector import PhishingDetector, PhishingAnalysisReport

# Initialize detector
detector = PhishingDetector()

# Analyze single URL
result = detector.detect("https://example.com", detailed=True)

# Generate analysis report
report_gen = PhishingAnalysisReport(detector)
report = report_gen.analyze_url("https://example.com")

# Analyze batch of URLs
batch_report = report_gen.analyze_batch([
    "https://google.com",
    "https://suspicious-site.com"
])

# Export report
print(report_gen.export_report(batch_report, format='text'))
```

#### Detection Characteristics:
- **URL Length Analysis**: Identifies unusually long URLs
- **Domain Structure**: Checks for suspicious subdomains
- **Protocol Validation**: Verifies HTTPS usage
- **IP Detection**: Identifies IP-based URLs
- **Special Characters**: Detects obfuscation techniques
- **Keyword Analysis**: Finds phishing-related keywords

#### Threat Levels:
- **CRITICAL** (80-100%): Block immediately
- **HIGH** (60-79%): Avoid and report
- **MEDIUM** (40-59%): Exercise caution
- **LOW** (20-39%): Likely safe
- **MINIMAL** (0-19%): Safe to use

---

## Repository Structure
```
Unkn0wx7-Tools/
├── phishing_detector.py       # Main phishing detection system
├── README.md                  # Documentation
├── requirements.txt           # Python dependencies
└── examples/                  # Usage examples
```

## Requirements
- Python 3.7+
- NumPy
- scikit-learn

## Installation & Setup

1. Clone the repository:
```bash
git clone https://github.com/Unkn0wx7/Unkn0wx7-Tools.git
cd Unkn0wx7-Tools
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run examples:
```bash
python phishing_detector.py
```

## License
MIT License - Feel free to use and modify

## Author
**Made By Unkn0wx7**

---

*More tools coming soon!*
