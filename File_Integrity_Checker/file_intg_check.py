import hashlib
import os
import json
import time

HASH_DB_FILE = "file_hashes.json"

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        print(f"[SKIPPED]   {file_path} - {e.__class__.__name__}")
        return None

def load_hash_database():
    if os.path.exists(HASH_DB_FILE):
        with open(HASH_DB_FILE, "r") as db_file:
            return json.load(db_file)
    return {}

def save_hash_database(db):
    with open(HASH_DB_FILE, "w") as db_file:
        json.dump(db, db_file, indent=4)

def monitor_files(monitor_dir):
    print("\n🔍 Scanning files for integrity...\n")
    current_hashes = {}
    stored_hashes = load_hash_database()

    for root, _, files in os.walk(monitor_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, monitor_dir)
            file_hash = calculate_hash(file_path)
            current_hashes[relative_path] = file_hash

            if relative_path not in stored_hashes:
                print(f"[NEW]       {relative_path}")
            elif stored_hashes[relative_path] != file_hash:
                print(f"[MODIFIED]  {relative_path}")

    for stored_file in stored_hashes:
        if stored_file not in current_hashes:
            print(f"[DELETED]   {stored_file}")

    save_hash_database(current_hashes)
    print("\n✅ Scan complete. Hash database updated.\n")

def reset_database():
    if os.path.exists(HASH_DB_FILE):
        os.remove(HASH_DB_FILE)
        print("\n⚠️ Hash database has been reset.\n")
    else:
        print("\nℹ️ No existing database to delete.\n")

def main():
    print("📁 File Integrity Checker - CodTech Internship Task 1")
    print("------------------------------------------------------")

    monitor_dir = input("📂 Enter the folder path to monitor (default: files_to_monitor): ").strip()
    if not monitor_dir:
        monitor_dir = "files_to_monitor"

    if not os.path.exists(monitor_dir):
        os.makedirs(monitor_dir)
        print(f"✅ Created monitoring folder: {monitor_dir}")

    while True:
        print("\nChoose an option:")
        print("1. Scan for changes")
        print("2. Reset hash database")
        print("3. Exit")

        choice = input("\nYour choice: ").strip()

        if choice == '1':
            monitor_files(monitor_dir)
        elif choice == '2':
            reset_database()
        elif choice == '3':
            print("\n👋 Exiting... Thank you!\n")
            break
        else:
            print("❌ Invalid input. Please enter 1, 2, or 3.")

        time.sleep(1)

if __name__ == "__main__":
    main()
