import sqlite3

database_path = 'data.db'

def add_ips():
    try:
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()
        
        # IP Range: 5.175.221.3 - 5.175.221.33
        base_prefix = "5.175.221."
        start = 3
        end = 33
        
        count = 0
        for i in range(start, end + 1):
            ip = f"{base_prefix}{i}"
            try:
                # Assuming table structure: ips (ip TEXT PRIMARY KEY, used INTEGER DEFAULT 0)
                # Or similar. We use INSERT OR IGNORE to avoid duplicates if rerun.
                cursor.execute("INSERT OR IGNORE INTO ips (ip, used) VALUES (?, 0)", (ip,))
                if cursor.rowcount > 0:
                    count += 1
            except Exception as e:
                print(f"Error inserting {ip}: {e}")
        
        conn.commit()
        conn.close()
        print(f"Successfully added {count} new IPs to the database.")
        
    except Exception as e:
        print(f"Database error: {e}")

if __name__ == "__main__":
    add_ips()
