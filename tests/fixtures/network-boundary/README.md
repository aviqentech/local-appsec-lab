# Boundary test
The JavaScript fixture /egress-probe attempts only 127.0.0.1:CANARY_PORT. Tests create a trusted local canary and assert the application cannot contact its unapproved port. No public destination is contacted.
