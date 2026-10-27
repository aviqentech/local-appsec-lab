$ErrorActionPreference = 'Stop'
python (Join-Path $PSScriptRoot 'install.py') @args
exit $LASTEXITCODE
