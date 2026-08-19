#!/usr/bin/env python3
"""
Windows Test Script for Phishing Detection System
Made By Unkn0wx7

Simple test script to run the phishing detector on Windows
with formatted output and analysis
"""

from phishing_detector import PhishingDetector, PhishingAnalysisReport

def main():
    # Initialize
    detector = PhishingDetector()
    report_gen = PhishingAnalysisReport(detector)

    # Test URLs
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "http://verify-account-urgent.com/login",
        "https://www.microsoft.com",
        "https://192.168.1.1/admin@bank.com/verify",
        "https://www.amazon.com"
    ]

    print("\n" + "="*70)
    print("PHISHING DETECTION SYSTEM - WINDOWS VERSION")
    print("Made By Unkn0wx7")
    print("="*70 + "\n")

    batch_report = report_gen.analyze_batch(urls)

    # Display individual analysis
    print("DETAILED URL ANALYSIS:")
    print("-" * 70 + "\n")

    for i, analysis in enumerate(batch_report['analyses'], 1):
        url = analysis['url']
        risk = analysis['detection']['risk_score']
        is_phishing = analysis['detection']['is_phishing']
        threat = analysis['summary']['threat_level']
        confidence = analysis['detection']['confidence']
        recommendation = analysis['summary']['recommendation']
        
        print(f"[{i}] URL: {url}")
        print(f"    Risk Score: {risk:.2f}%")
        print(f"    Threat Level: {threat}")
        print(f"    Is Phishing: {is_phishing}")
        print(f"    Confidence: {confidence:.2f}%")
        print(f"    Recommendation: {recommendation}")
        print()

    # Display summary
    print("="*70)
    print("BATCH ANALYSIS SUMMARY:")
    print("="*70)
    print(f"Total URLs Analyzed: {batch_report['total_urls']}")
    print(f"Phishing Detected: {batch_report['summary']['phishing_detected']}")
    print(f"Phishing Percentage: {batch_report['summary']['phishing_percentage']:.2f}%")
    print(f"Average Risk Score: {batch_report['summary']['average_risk_score']:.2f}%")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
