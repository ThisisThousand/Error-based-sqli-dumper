# 🚀 High-Performance Async SQLi Engine (v3.0)

## Description
Advanced data exfiltration engine designed for authorized security audits. This tool specializes in high-speed extraction via **Error-Based SQL Injection**, utilizing an asynchronous architecture to maximize throughput in controlled environments.

Unlike traditional sequential scripts, this engine leverages **Python's `asyncio` stack** to handle massive data volumes with minimal latency.

---

## 🔥 Key Engineering Features

* **Producer-Consumer Architecture:** Uses an asynchronous **Worker-Queue** pattern to process database offsets independently, ensuring 100% resource utilization.
* **Dual-Queue I/O Management:** Separate queues for network requests and disk writes (I/O) to prevent bottlenecks and ensure data integrity.
* **Multi-Endpoint Rotation:** Support for multiple target URLs with automated rotation to bypass simple rate-limiting and distribute load.
* **Pre-flight Vulnerability Check:** Automated verification of the injection vector and regex pattern matching before initiating full-scale exfiltration.
* **WAF Evasion Logic:** Optimized payloads with 'AND balance' techniques (`AND '1'='1`) and `updatexml()` error triggers for better stability against basic security filters.
* **Automated Schema Mapping:** Recursive discovery of databases, tables, and columns via `information_schema` without prior knowledge of the target structure.
* **Safe SQL Reconstruction:** Real-time data sanitization and escaping to generate ready-to-import `.sql` files.



---

## ⚙️ Technical Specifications

| Feature | Implementation |
| :--- | :--- |
| **Concurrency** | `asyncio` + `Semaphore` |
| **HTTP Client** | `httpx` (Asynchronous) |
| **Payload Vector** | XPATH Error-Based (`updatexml`) |
| **Data Flow** | Independent Workers + `asyncio.Queue` |
| **Compatibility** | MySQL / MariaDB |

---

## 🛠️ Usage

```bash
# Basic usage with multiple endpoints and concurrency control
python sqli_dumper.py -u "[http://target1.com/api,http://target2.com/api](http://target1.com/api,http://target2.com/api)" -i 77 -d target_db -c 15
