#  Phishing Email Analyzer

> **A comprehensive cybersecurity solution for detecting phishing emails through email header analysis, authentication validation, heuristic risk scoring, and an interactive SOC-style dashboard.**



##  Overview

Phishing Email Analyzer is a cybersecurity project developed to identify malicious emails by analyzing their metadata, authentication results, routing information, and content-based indicators. The system combines rule-based detection with transparent scoring to produce an explainable phishing risk assessment.

Unlike machine learning models that require extensive datasets and training, this analyzer uses deterministic security rules inspired by real-world email security standards such as **SPF**, **DKIM**, and **DMARC**, making it reliable, offline-capable, and ideal for educational demonstrations, security awareness, and hackathons.

The project also includes a modern **React-based Security Operations Center (SOC) dashboard** that provides a real-time visualization of the complete email analysis pipeline.



#  Objectives

* Detect phishing emails using explainable cybersecurity techniques.
* Analyze raw email headers (.eml files).
* Validate email authentication mechanisms.
* Extract routing information and originating IP addresses.
* Generate a transparent phishing risk score.
* Produce detailed HTML reports.
* Demonstrate modern phishing detection using an interactive dashboard.



#  Features

## Email Header Analysis

* Parses raw email (.eml) files
* Extracts sender information
* Reads email routing path
* Identifies originating IP address
* Detects Reply-To manipulation
* Detects Return-Path inconsistencies



## Authentication Validation

* SPF Verification
* DKIM Verification
* DMARC Verification



## Threat Detection

* Suspicious keyword detection
* URL inspection
* Reply-To mismatch detection
* Domain alignment verification
* Public IP extraction
* Private/Public IP identification



## Risk Scoring

Each suspicious indicator contributes to a transparent phishing score.

Risk Levels

| Score  | Threat Level |
| ------ | ------------ |
| 0-25   | 🟢 Low       |
| 26-50  | 🟡 Medium    |
| 51-75  | 🟠 High      |
| 76-100 | 🔴 Critical  |

---

## Interactive Dashboard

* SOC-inspired interface
* Real-time analysis
* Drag & Drop .eml upload
* Threat gauge visualization
* Live signal log
* Authentication status display
* Risk scoring animation



# 📄 File Description

## phishing_analyzer.py

Main analysis engine.

Responsibilities

* Parse raw emails
* Read headers
* Extract sender information
* Validate SPF
* Validate DKIM
* Validate DMARC
* Extract IP addresses
* Analyze Reply-To
* Analyze Return-Path
* Detect suspicious keywords
* Analyze embedded URLs
* Generate phishing score
* Produce HTML reports

---

## phishing_sample.eml

A simulated phishing email used for testing.

Contains

* Fake sender
* Authentication failures
* Suspicious URLs
* Urgent language
* Domain spoofing

---

## legit_sample.eml

A legitimate email sample used for comparison.

Contains

* Valid authentication
* Legitimate routing
* Clean sender information
* Normal content

---

## phishing_report.html

HTML report generated after analyzing the phishing email.

Displays

* Threat level
* Authentication results
* Risk score
* Triggered security rules

---

## legit_report.html

Generated report for a legitimate email.

Shows

* Successful authentication
* Low risk
* Clean routing

---

## PhishingConsole.jsx

Interactive React dashboard.

Features

* Drag-and-drop upload
* Real-time scoring
* Threat visualization
* Security pipeline display
* Signal breakdown
* Dashboard analytics


# Security Pipeline


                 RAW EMAIL (.eml)
                        │
                        ▼
             Email Header Parsing
                        │
                        ▼
          Authentication Extraction
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
      SPF            DKIM            DMARC
        │               │               │
        └───────────────┼───────────────┘
                        ▼
          Routing & IP Address Analysis
                        │
                        ▼
       Domain Alignment Verification
                        │
                        ▼
        Reply-To & Return-Path Analysis
                        │
                        ▼
        Keyword & URL Inspection
                        │
                        ▼
         Heuristic Rule Evaluation
                        │
                        ▼
            Suspiciousness Score
                        │
                        ▼
           Threat Classification
                        │
                        ▼
          HTML Report & React Dashboard




# Email Authentication

## SPF

Verifies whether the sender's mail server is authorized to send emails on behalf of the domain.



## DKIM

Uses cryptographic signatures to verify that the email has not been modified during transmission.



## DMARC

Ensures alignment between the visible sender domain and the domains validated by SPF or DKIM, and specifies how failed messages should be handled.

# ⚙ Detection Workflow

1. Load raw email (.eml)
2. Parse email headers
3. Read Authentication-Results
4. Validate SPF
5. Validate DKIM
6. Validate DMARC
7. Extract Received headers
8. Identify originating IP
9. Compare sender domains
10. Analyze Reply-To
11. Analyze Return-Path
12. Inspect keywords
13. Analyze URLs
14. Apply heuristic rules
15. Calculate phishing score
16. Generate HTML report
17. Display interactive dashboard



# Scoring Factors

| Security Check       | Risk Impact |
| -------------------- | ----------- |
| SPF Fail             | High        |
| DKIM Fail            | High        |
| DMARC Fail           | High        |
| Reply-To mismatch    | Medium      |
| Return-Path mismatch | Medium      |
| Public suspicious IP | Medium      |
| Suspicious keywords  | Medium      |
| Malicious URLs       | High        |
| Domain spoofing      | High        |



# Backend

* Python
* email
* re
* ipaddress
* html

 Frontend
* React
* Vite
* JavaScript
* Tailwind CSS
* Lucide React


# Future Enhancements

* VirusTotal integration
* AbuseIPDB reputation lookup
* URL reputation analysis
* Attachment malware scanning
* Homograph attack detection
* Typosquatting detection
* Batch email analysis
* IMAP inbox monitoring
* PDF report generation
* REST API integration
* AI-assisted phishing explanation
* Threat intelligence feeds



# Applications

* Email security education
* Cybersecurity awareness
* Security Operations Centers (SOC)
* Academic research
* Ethical hacking demonstrations
* Blue-team training
* Hackathons
* Enterprise email security concepts



**Why This Project?**

Unlike many phishing detection projects that rely solely on machine learning, this analyzer emphasizes **explainable cybersecurity**. Every risk score is backed by transparent security rules, making it easier to understand *why* an email is considered suspicious. This makes the project suitable for learning, demonstrations, and environments where interpretability is as important as detection accuracy.


Author

**Monika Gajapathy**
**B.Tech Artificial Intelligence & Data Science**

If you found this project useful, consider giving it a ⭐ on GitHub!
