🚀 Asynchronous SQL Injection Data Extraction Engine

📝 Description
This project is an asynchronous SQL injection data extraction engine designed for controlled environments and authorized security testing.

It focuses on automating the process of:

* Database schema enumeration
* Table and column discovery
* Structured data extraction

The tool leverages Python’s asyncio ecosystem to improve efficiency over traditional sequential approaches.

⚙️ Core Features

* Asynchronous Architecture

  * Built with asyncio and httpx for concurrent request handling
  * Uses semaphores to control concurrency and avoid overload

* Batch-Based Extraction

  * Processes multiple offsets in parallel to improve throughput
  * Reduces idle time compared to sequential dumping

* Schema Mapping

  * Automatically enumerates:

    * Databases
    * Tables
    * Columns
  * Uses information_schema for discovery

* Error-Based Extraction

  * Implements MySQL error-based techniques (updatexml)
  * Parses responses to extract query results

* SQL Reconstruction

  * Generates .sql output including:

    * CREATE TABLE statements
    * INSERT INTO data dumps
  * Basic sanitization for safe output formatting

* Multi-endpoint Support

  * Rotates between multiple target endpoints to distribute load

🛠️ Usage

python sqli_dumper.py -u "http://target.com/api" -i 77 -d target_db

Arguments:

* -u → Target URL (comma-separated for multiple endpoints)
* -i → Vulnerable numeric parameter
* -d → Target database name

🧪 Example Workflow

1. Identify injectable parameter
2. Map database structure
3. Extract table data asynchronously
4. Generate .sql dump for analysis

⚠️ Limitations

* Focused on error-based SQL injection (MySQL/MariaDB)
* Does not include:

  * Boolean-based or time-based techniques
  * Advanced WAF bypass mechanisms
* Results depend on:

  * Error visibility
  * Target behavior
* Large datasets may require tuning of:

  * Concurrency
  * Batch size

🧠 Technical Stack

| Component     | Technology          |
| ------------- | ------------------- |
| Concurrency   | asyncio + Semaphore |
| HTTP Client   | httpx (async)       |
| Extraction    | Error-based SQLi    |
| Data Handling | Python I/O          |

⚖️ Legal & Ethical Notice

This tool is intended strictly for educational purposes and authorized security testing.

By using this software, you agree to:

* Only test systems you own or have explicit permission to assess
* Comply with all applicable laws and regulations
* Take full responsibility for your actions

Unauthorized use may be illegal.
