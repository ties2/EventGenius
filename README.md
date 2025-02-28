EventGenius
EventGenius is a Python-based tool that leverages RAG (Retrieval-Augmented Generation) AI to analyze event codes from a PDF and generate detailed use cases for different types of attacks. This tool is designed to assist Security Operations Center (SOC) analysts in understanding and responding to security incidents more effectively.

Features

Event Code Analysis: Extracts and analyzes event codes from a PDF document.
Use Case Generation: Generates detailed use cases for various attack scenarios (e.g., unauthorized access, malware execution, data exfiltration).
RAG AI Integration: Uses the facebook/rag-sequence-base model to retrieve and generate context-aware responses.
SOC-Friendly: Designed to help SOC analysts quickly understand and respond to security incidents.
Installation

Prerequisites

Python 3.8 or higher
Git (optional, for cloning the repository)
Steps

Clone the Repository:
``` Bash
git clone https://github.com/your-username/EventGenius.git
cd EventGenius
```
Set Up a Virtual Environment (optional but recommended):
``` Bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
Install Dependencies:
pip install -r requirements.txt

Usage

Run the Script:
``` Bash
python EventGenius.py

```
Generate Use Cases:
The script will analyze the event codes and generate use cases for different attack types. Example output:

Use Case for Unauthorized Access Attempt:
An attacker attempts to log in to a system using incorrect credentials. The event code 4625 (FAILED_LOGON) is triggered...

Contact

For questions or feedback, please contact:
Your Name
Email: your-email@example.com
GitHub: your-username