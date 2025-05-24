# Packer Detector

## Overview
Packer Detector is a security tool designed to identify and analyze executable files that have been packed with various packers. It uses YARA rules to detect potential malware hidden through packing techniques. The application provides a user-friendly interface for scanning individual files or entire directories, quarantining suspicious files, and maintaining detection logs for security analysis.

## Features
- **YARA-based Detection**: Utilizes YARA rules to identify various packer signatures in executable files
- **File and Directory Scanning**: Scan individual files or entire directories with recursive option
- **Automatic Quarantine**: Automatically moves detected files to a quarantine directory with restricted permissions
- **Detection Logging**: Maintains a comprehensive log of all detections including timestamps, file paths, SHA256 hashes, and matching rules
- **User-friendly Interface**: Dark-themed modern interface with color-coded results for easy interpretation
- **Detailed Results**: Provides detailed information about detected files including SHA256 hash, packer types, and matching rules

## Requirements
- Windows operating system
- YARA engine (yara64.exe)
- Python 3.x with the following packages:
  - tkinter
  - ttkbootstrap
  - PIL (Pillow)

## Installation
1. Clone or download this repository
2. Ensure YARA is installed and accessible (default path: `E:\NT230\coursework\yara-v4.5.2-2326-win64\yara64.exe`)
3. Install required Python packages:
   ```bash
   pip install ttkbootstrap pillow
   ```
