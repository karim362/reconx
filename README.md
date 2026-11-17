# ReconX v3.0

Professional reconnaissance framework for Termux.

## Features
- 7 passive sources
- DNS bruteforce (5000 words)
- Permutations generator
- httpx batch scanning with early-stop
- DNS pre-filter (80% faster)
- Deep probing
- BFS crawler with forms/params
- Takeover detection (13 services)
- Nuclei scanning
- Multi-output (txt, csv, json, md, html, sqlite)
- Resume support

## Install

    pkg install python git golang
    pip install requests dnspython rich beautifulsoup4 lxml urllib3 PyYAML
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates

## Usage

    python -m reconx -d example.com --all -t 15
    python -m reconx -d example.com --fast
    python -m reconx -dL scope.txt --all
    python -m reconx -d example.com --resume

## Legal

Only scan domains you own or have written permission to test.
