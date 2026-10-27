# Methodology

Start from actual files and framework evidence. Prefer parsing manifests, Python AST
and OpenAPI to guessing. Built-in source rules are syntactic candidate discovery,
not whole-program data-flow analysis. Use synthetic identities and a known marker
to test ownership: the owner must first receive the record, the disallowed actor
must not receive it, and an independent repeat must reproduce the behavior.
Secure negative controls must remain absent from confirmed results. Use OWASP
WSTG/ASVS and CWE as methodology references, not certification claims.
