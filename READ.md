# PhishGuard – Phishing Awareness & Suspicious Link Reporting System

Beginner-friendly defensive cybersecurity website for detecting suspicious links and phishing patterns, reporting content, learning awareness topics, and chatting with a local AI assistant.

**Important:** This project never opens, visits, or executes URLs. Analysis uses text/structure only.

## Features

- Suspicious Link Checker (structure-based risk score)
- Phishing Email Analyzer
- Report center (SQLite)
- Awareness articles + red flags + quiz
- PhishGuard AI chatbot (local fallback, API-ready)
- Live stats dashboard
- Dark cyber UI, glassmorphism, responsive layout

## Setup

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
# source venv/bin/activate

pip install -r requirements.txt
python app.py