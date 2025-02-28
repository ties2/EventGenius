"""
Dataset containing Windows Event IDs and their corresponding event names
"""

EVENT_CODES = [
    {"event_id": "4720", "event_name": "A user account was created"},
    {"event_id": "4722", "event_name": "A user account was enabled"},
    {"event_id": "4723", "event_name": "An attempt was made to change an account's password"},
    {"event_id": "4724", "event_name": "An attempt was made to reset an account's password"},
    {"event_id": "4725", "event_name": "A user account was disabled"},
    {"event_id": "4726", "event_name": "A user account was deleted"},
    {"event_id": "4738", "event_name": "A user account was changed"},
    {"event_id": "4740", "event_name": "A user account was locked out"},
    {"event_id": "4767", "event_name": "A user account was unlocked"},
    {"event_id": "4727", "event_name": "A security-enabled global group was created"},
    {"event_id": "4730", "event_name": "A security-enabled global group was deleted"},
    {"event_id": "4731", "event_name": "A security-enabled local group was created"},
    {"event_id": "4734", "event_name": "A security-enabled local group was deleted"},
    {"event_id": "4754", "event_name": "A security-enabled universal group was created"},
    {"event_id": "4758", "event_name": "A security-enabled universal group was deleted"},
    {"event_id": "4728", "event_name": "A member was added to a security-enabled global group"},
    {"event_id": "4729", "event_name": "A member was removed from a security-enabled global group"},
    {"event_id": "4732", "event_name": "A member was added to a security-enabled local group"},
    {"event_id": "4733", "event_name": "A member was removed from a security-enabled local group"},
    {"event_id": "4756", "event_name": "A member was added to a security-enabled universal group"},
    {"event_id": "4757", "event_name": "A member was removed from a security-enabled universal group"},
    {"event_id": "4625", "event_name": "FAILED LOGON"},
    {"event_id": "4104", "event_name": "POWERSHELL SCRIPT EXECUTION"},
    {"event_id": "5145", "event_name": "FILE SHARE ACCESS"},
    {"event_id": "4674", "event_name": "PRIVILEGE ELEVATION"},
    {"event_id": "1102", "event_name": "LOG CLEAR"},
    {"event_id": "4648", "event_name": "EXPLICIT CREDENTIAL LOGON"},
    {"event_id": "4663", "event_name": "FILE DELETED"},
    {"event_id": "7045", "event_name": "SERVICE INSTALLED"},
    {"event_id": "4688", "event_name": "PROCESS CREATED"},
    {"event_id": "4697", "event_name": "SERVICE CREATED"},
    {"event_id": "4698", "event_name": "SCHEDULED TASK CREATED"},
    {"event_id": "4672", "event_name": "SPECIAL PRIVILEGES ASSIGNED"},
    {"event_id": "4673", "event_name": "TOKEN PRIVILEGES MODIFIED"},
    {"event_id": "4103", "event_name": "ENGINE LIFECYCLE"},
    {"event_id": "5859", "event_name": "WMI EVENT FILTER TO CONSUMER BINDING"},
    {"event_id": "5858", "event_name": "WMI ACTIVITY EXECQUERY"},
    {"event_id": "5157", "event_name": "FIREWALL BLOCK"},
    {"event_id": "7000", "event_name": "SERVICE START FAILED"},
    {"event_id": "4660", "event_name": "OBJECT DELETED"},
    {"event_id": "4689", "event_name": "PROCESS TERMINATED"},
    {"event_id": "7034", "event_name": "SERVICE CRASHED"},
    {"event_id": "4226", "event_name": "TCP/IP CONNECTION LIMIT REACHED"}
]

# Add semantic mapping of event IDs to attack types for better retrieval
ATTACK_PATTERNS = {
    "Unauthorized Access Attempt": [
        "4625", "4740", "4767", "4648", "4625"
    ],
    "Account Manipulation": [
        "4720", "4722", "4723", "4724", "4725", "4726", "4738", "4740", "4767"
    ],
    "Privilege Escalation": [
        "4672", "4673", "4674", "4728", "4732", "4756"
    ],
    "Lateral Movement": [
        "4648", "4624", "4688", "5145"
    ],
    "Defense Evasion": [
        "1102", "4689", "4660"
    ],
    "Credential Access": [
        "4723", "4724"
    ],
    "Discovery": [
        "4688", "4103", "4104", "5145"
    ],
    "Collection": [
        "5145", "4663", "4660"
    ],
    "Command and Control": [
        "5157", "4226", "4688"
    ],
    "Exfiltration": [
        "5145", "4663"
    ],
    "Impact": [
        "7045", "7000", "7034", "4689", "1102"
    ],
    "Persistence": [
        "4698", "4697", "7045", "5859", "5858"
    ],
    "Execution": [
        "4688", "4104", "4103", "4697", "7045"
    ],
    "Malware Execution": [
        "4688", "4104", "7045", "4697", "4698"
    ],
    "Data Exfiltration": [
        "5145", "4663", "4688", "5157"
    ],
    "Phishing Attack": [
        "4688", "4104", "4663", "4697", "4698"
    ]
}

# Add more detailed descriptions to enhance use case generation
EVENT_DESCRIPTIONS = {
    "4625": "Indicates a failed login attempt, which could be part of a brute force attack or stolen credential usage.",
    "4720": "A new user account was created, potentially indicating account creation for persistence or unauthorized access.",
    "4672": "Special privileges were assigned to a new logon, which might indicate privilege escalation.",
    "4697": "A service was installed in the system, often used by malware for persistence.",
    "4688": "A new process was created, which could indicate execution of malicious code.",
    "4104": "PowerShell script block logging, often indicating script-based attacks or living-off-the-land techniques.",
    "5145": "A network share object was checked to see whether client can access it, potential data exfiltration indicator.",
    "1102": "The audit log was cleared, a common technique to cover tracks after an attack.",
    "4698": "A scheduled task was created, commonly used for persistence mechanisms.",
    "7045": "A new service was installed, which could be malware establishing persistence.",
    "4663": "An attempt was made to access an object, potentially indicating unauthorized data access.",
    "5859": "WMI Event Consumer binding, often used in sophisticated persistence techniques.",
    "4740": "A user account was locked out, could indicate brute force password attacks.",
    "4648": "A logon was attempted using explicit credentials, potential lateral movement indicator."
}

# Combine some events into attack chain examples
ATTACK_CHAINS = {
    "Ransomware Attack": [
        {"sequence": 1, "event_id": "4625", "context": "Multiple failed login attempts"},
        {"sequence": 2, "event_id": "4688", "context": "Suspicious process execution from email attachment"},
        {"sequence": 3, "event_id": "4104", "context": "PowerShell script execution for lateral movement"},
        {"sequence": 4, "event_id": "5145", "context": "Scanning network shares for valuable data"},
        {"sequence": 5, "event_id": "4663", "context": "Mass file encryption operations"},
        {"sequence": 6, "event_id": "1102", "context": "Log clearing to cover tracks"}
    ],
    "Data Theft": [
        {"sequence": 1, "event_id": "4648", "context": "Login with stolen credentials"},
        {"sequence": 2, "event_id": "4672", "context": "Privilege escalation to admin rights"},
        {"sequence": 3, "event_id": "4688", "context": "Execution of data collection tools"},
        {"sequence": 4, "event_id": "5145", "context": "Access to sensitive file shares"},
        {"sequence": 5, "event_id": "4663", "context": "Mass copying of sensitive files"},
        {"sequence": 6, "event_id": "5157", "context": "Data exfiltration blocked by firewall"}
    ],
    "Insider Threat": [
        {"sequence": 1, "event_id": "4672", "context": "Employee using privileged access"},
        {"sequence": 2, "event_id": "5145", "context": "Accessing shares outside normal pattern"},
        {"sequence": 3, "event_id": "4663", "context": "Copying sensitive intellectual property"},
        {"sequence": 4, "event_id": "4688", "context": "Executing file compression tools"},
        {"sequence": 5, "event_id": "4648", "context": "Using credentials during off-hours"}
    ]
}