# Enterprise Password Strength Analyzer

A professional GUI tool for analyzing password strength with detailed feedback and suggestions.

## Features

- Real-time password strength analysis
- Detailed feedback on password weaknesses
- Strong password generation
- Dictionary word detection (with NLTK)
- Common pattern recognition
- Entropy calculation

## Installation (Kali Linux)

### Prerequisites
- Python 3.8+
- pip
- venv module (usually included with Python)

### Using Virtual Environment (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-strength-checker.git
   cd password-strength-checker
   ```
2.Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
3.Install dependencies:
```bash
pip install -r password_strength/requirements.txt
```
4.Download NLTK data:
```bash
python -c "import nltk; nltk.download('words')"
```
5.Running the Application
```bash
# Activate virtual environment if not already active
source venv/bin/activate

# Run the application
python -m password_strength.checker
```
