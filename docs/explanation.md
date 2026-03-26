# SQL Injection – Error-Based Exploitation

## Overview

This document explains how error-based SQL Injection works and how it is used in this project to extract data from a vulnerable database.

---

## What is SQL Injection?

SQL Injection is a vulnerability that allows an attacker to manipulate SQL queries by injecting malicious input.

This happens when:

* User input is not validated
* Queries are dynamically built
* No parameterized queries are used

### Impact:

* Data leakage
* Authentication bypass
* Database manipulation

---

## Error-Based SQL Injection

Error-based SQL Injection relies on extracting information from database error messages.

Instead of guessing values blindly, the attacker:

1. Forces the database to throw an error
2. Embeds data inside the error message
3. Extracts the data from the response

---

## Exploitation Technique Used

This project uses a MySQL-specific technique based on:

* `RAND()`
* `GROUP BY`
* `COUNT(*)`
* `CONCAT()`

### Why it works:

* `RAND(0)` generates predictable values
* Combined with `GROUP BY`, it creates duplicate entries
* MySQL throws a "Duplicate entry" error
* The injected data is included in that error

---

## Data Extraction Strategy

The tool extracts data using a structured approach:

### 1. Wrap data

The extracted value is wrapped with delimiters:

```
~value~
```

### 2. Trigger error

The payload forces a duplicate entry error containing the wrapped value.

### 3. Parse response

A regex extracts the value:

```
Duplicate entry '~value~'
```

---

## Enumeration Process

### Step 1: Databases

Query:

```
information_schema.schemata
```

### Step 2: Tables

Query:

```
information_schema.tables
```

### Step 3: Columns

Query:

```
information_schema.columns
```

### Step 4: Data

* Uses `LIMIT offset,1`
* Extracts row by row
* Combines columns using `CONCAT()`

---

## HEX Encoding

Database and table names are converted to HEX format to:

* Avoid syntax errors
* Bypass filtering
* Increase reliability

Example:

```
users → 0x7573657273
```

---

## Output Reconstruction

The extracted data is converted into SQL format:

* `CREATE DATABASE`
* `CREATE TABLE`
* `INSERT INTO`

This allows rebuilding the database locally.

---

## Mitigation

To prevent SQL Injection:

* Use parameterized queries (prepared statements)
* Validate and sanitize inputs
* Avoid dynamic SQL queries
* Disable detailed error messages
* Use ORM frameworks

---

## Conclusion

This project demonstrates:

* Practical exploitation of SQL Injection
* Understanding of database behavior
* Automation of offensive techniques

⚠️ This is strictly for educational purposes and must only be used in authorized environments.
