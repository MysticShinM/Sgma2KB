import os
import csv
import yaml
import re
import pandas as pd

def clean_tags(tags):
    if isinstance(tags, list):
        tags = [str(tag) for tag in tags]
        cleaned = [re.sub(r'[-_]', ' ', tag).replace('attack.', '') for tag in tags]
        return ', '.join(cleaned)
    elif isinstance(tags, str):
        return re.sub(r'[-_]', ' ', tags).replace('attack.', '')
    return ""

def format_tags(tags):
    if isinstance(tags, list):
        return ', '.join(str(tag) for tag in tags)
    return str(tags) if tags is not None else ""

def load_csv(file_path):
    return pd.read_csv(file_path, dtype=str).fillna('')

def match_tags(tags, reference_df):
    tags_set = set(tag.strip().lower() for tag in tags.split(',') if tag.strip())
    matched_ids, matched_names = [], []
    for _, row in reference_df.iterrows():
        if str(row['ID']).lower() in tags_set or str(row['name']).lower() in tags_set:
            matched_ids.append(row['ID'])
            matched_names.append(row['name'])
    return ', '.join(matched_ids), ', '.join(matched_names)

def fill_tactics_from_techniques(row, techniques_df, tactics_df):
    if not row.get("tactics_id") and row.get("techniques_id"):
        tactics_names = []
        for tech_id in row["techniques_id"].split(','):
            tech_id = tech_id.strip()
            matched = techniques_df[techniques_df['ID'].str.strip() == tech_id]
            if not matched.empty:
                tactics = matched.iloc[0]['tactics']
                if pd.notna(tactics):
                    tactics_names += [t.strip() for t in tactics.split(',')]
        matched_ids, matched_names = match_tags(', '.join(tactics_names), tactics_df)
        row["tactics_id"] = matched_ids
        row["tactics_name"] = matched_names
    return row

def split_file_path(file_path):
    parts = file_path.split(os.sep)
    type_folder = parts[0] if parts else ""
    datasource = os.sep.join(parts[1:]) if len(parts) > 1 else ""
    return type_folder, datasource

def extract_yaml_to_csv(root_dir, output_csv, tactics_csv_path, techniques_csv_path):
    tactics_df = load_csv(tactics_csv_path)
    techniques_df = load_csv(techniques_csv_path)
    columns = [
        "date", "modified", "Type", "Datasource", "tags", "original_tags",
        "tactics_id", "tactics_name", "techniques_id", "techniques_name",
        "logsource", "title", "description", "detection", "falsepositives",
        "fields", "level", "references", "File path", "file name"
    ]
    data_rows = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if not file.lower().endswith(('.yml', '.yaml')):
                continue
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, root_dir)
            row = {key: "" for key in columns}
            row["File path"] = os.path.dirname(relative_path)
            row["file name"] = file
            row["Type"], row["Datasource"] = split_file_path(row["File path"])
            try:
                with open(file_path, 'r', encoding='utf-8') as yaml_file:
                    content = yaml.safe_load(yaml_file) or {}
                    row["date"] = content.get("date", "")
                    row["modified"] = content.get("modified", "")
                    original_tags = content.get("tags", "")
                    row["original_tags"] = format_tags(original_tags)
                    row["tags"] = clean_tags(original_tags)
                    row["logsource"] = format_tags(content.get("logsource", ""))
                    row["title"] = content.get("title", "")
                    row["description"] = content.get("description", "")
                    row["detection"] = format_tags(content.get("detection", ""))
                    row["falsepositives"] = format_tags(content.get("falsepositives", ""))
                    row["fields"] = ', '.join(content.get("fields", [])) if isinstance(content.get("fields"), list) else format_tags(content.get("fields", ""))
                    row["level"] = content.get("level", "")
                    row["references"] = ', '.join(content.get("references", [])) if isinstance(content.get("references"), list) else format_tags(content.get("references", ""))
                    if row["tags"]:
                        row["tactics_id"], row["tactics_name"] = match_tags(row["tags"], tactics_df)
                        row["techniques_id"], row["techniques_name"] = match_tags(row["tags"], techniques_df)
                    row = fill_tactics_from_techniques(row, techniques_df, tactics_df)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
            data_rows.append(row)
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(data_rows)
    print(f"\nData extracted and saved to: {output_csv}")

if __name__ == "__main__":
    root_directory = input("Root directory containing YAML files: ").strip()
    tactics_csv_path = input("Path to tactics.csv: ").strip()
    techniques_csv_path = input("Path to techniques.csv: ").strip()
    output_csv_file = input("Output CSV file path: ").strip()
    extract_yaml_to_csv(root_directory, output_csv_file, tactics_csv_path, techniques_csv_path)
