#will create a temp dir and grab enterprise-attack-18.1
New-Item c:\temp -ItemType Directory -Force | Out-Null
Invoke-RestMethod "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack-18.1.json" -OutFile .\enterprise_attack.json