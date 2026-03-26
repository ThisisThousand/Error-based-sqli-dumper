# Error-Based SQL Injection Dumper

## Description
Automated error-based SQL injection tool for database enumeration and data extraction (educational use only).

This Python project demonstrates how an error-based SQL injection vulnerability can be exploited in a controlled lab environment to enumerate databases, tables, columns, and extract data.

---

## Features

- Enumerate all databases
- List tables and columns
- Dump full table data
- Generate SQL file for reconstruction
- Fully automated with Python

---

## How it Works

1. Exploits error-based SQL injection in MySQL.
2. Uses `Duplicate entry` error messages to extract data.
3. Wraps extracted data with delimiters (`~value~`) and parses it.
4. HEX encodes database/table names to avoid syntax issues.
5. Automates enumeration and dumping of databases, tables, and rows.

---

## Limitations
- Only works on error-based SQL injection
- Requires verbose database error messages
- MySQL-specific behavior

---

## Usage

```bash
python sqli_dumper.py -u http://example.com/vulnerable-endpoint -o dump.sql
