# SentinelX

**SentinelX** is a Windows-friendly Python CLI security utility for local file integrity monitoring and pattern-based secret scanning.

> Author: **Snayza** · Version: 1.0.0 · Python 3.10+


![image alt]( https://github.com/Snayza/SNAYZA-SentinelX/blob/main/Screenshot%202026-10-12%20222623.png?raw=true )

## Features

- SHA-256 file fingerprints and integrity baseline
- Reports added, modified, and missing files
- Scans common source/configuration files for likely exposed credentials
- Masks matched values in output to reduce accidental disclosure
- Colorful terminal dashboard (Colorama is optional)
- No network calls; scanning is local

## Requirements

- Windows 10/11
- Python 3.10 or newer

## Quick start (Windows)

1. Extract the ZIP into a folder, for example `C:\Tools\SentinelX`.
2. Open that folder in File Explorer.
3. Click the address bar, type `cmd`, and press Enter.
4. Check Python:

   ```bat
   py --version
   ```

5. (Optional) Install terminal colors:

   ```bat
   py -m pip install colorama
   ```

6. Start the interactive dashboard:

   ```bat
   py main.py
   ```

## CLI commands

Create a baseline for the folder you want to monitor:

```bat
py main.py init --path "C:\Users\YourName\Documents\MyProject"
```

Check for file changes:

```bat
py main.py integrity --path "C:\Users\YourName\Documents\MyProject"
```

Scan for possible secrets:

```bat
py main.py secrets --path "C:\Users\YourName\Documents\MyProject"
```

Show baseline status:

```bat
py main.py status --path "C:\Users\YourName\Documents\MyProject"
```

Include hidden files/folders (for example, `.github`) by adding `--include-hidden` to a command.

## How integrity monitoring works

The `init` command creates `.sentinelx_baseline.json` in the target directory. It stores each eligible file's relative path, size, and SHA-256 hash. The `integrity` command compares the current file hashes to the saved baseline.

**Important:** the baseline is stored beside the monitored files, so someone who can alter the directory can also alter the baseline. For stronger monitoring, keep a trusted copy of the baseline outside the monitored directory and compare against it. The baseline JSON is automatically excluded from scanning.

## Secret scanning notes

Secret scanning is based on patterns, not a full semantic analysis. It can miss unknown formats and may report false positives. Findings show a masked preview instead of the full matched value. Rotate any credential that you confirm was exposed, and remove it from source control history where appropriate.

## Safety and limitations

- Use only on folders you own or are authorized to inspect.
- Files larger than 25 MiB are skipped by integrity scanning.
- Common build/cache folders such as `.git`, `.venv`, `venv`, `node_modules`, and `__pycache__` are excluded by default.
- This is a portfolio/learning tool, not a replacement for endpoint detection, a SIEM, or a dedicated secrets-management solution.

## Project structure

```text
SentinelX/
├── main.py
├── README.md
└── LICENSE
```

## License

Released under the MIT License. See [LICENSE](LICENSE).
