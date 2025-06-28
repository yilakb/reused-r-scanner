import json
import csv

# Read the JSON file
with open('recovered_pk.json', 'r') as f:
    data = json.load(f)

# Filter for entries where both tx1_match and tx2_match are true
filtered_data = [entry for entry in data if entry.get('tx1_match') == True and entry.get('tx2_match') == True]

# Remove duplicates based on private_key
unique_data = {}
for entry in filtered_data:
    private_key = entry['private_key']
    if private_key not in unique_data:
        unique_data[private_key] = entry

# Convert to list
final_data = list(unique_data.values())

# Sort by private_key
final_data.sort(key=lambda x: x['private_key'])

print(f"Found {len(final_data)} entries with both tx1_match and tx2_match as true")

# Write to CSV
with open('recovered_Private_Key.txt', 'w', newline='', encoding='utf-8') as f:
    if final_data:
        writer = csv.DictWriter(f, fieldnames=['private_key', 'uncompressed_address', 'compressed_address'])
        writer.writeheader()
        for entry in final_data:
            writer.writerow({
                'private_key': entry['private_key'],
                'uncompressed_address': entry['uncompressed_address'],
                'compressed_address': entry['compressed_address']
            })

print("✅ Output written to: recovered_Private_Key.txt") 