import argparse
from pathlib import Path
import pandas as pd
import yaml
import re
import csv
from tqdm import tqdm
import logging

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
    if isinstance(tags, dict):
        return ', '.join(f"{k}:{v}" for k,v in tags.items())
    return str(tags) if tags is not None else ""

def load_csv(file_path):
    return pd.read_csv(file_path, dtype=str).fillna('')

def build_lookup(reference_df):
    id_lookup = {}
    name_lookup = {}
    for _, row in reference_df.iterrows():
        id_lookup[str(row['ID']).strip().lower()] = row['ID']
        name_lookup[str(row['name']).strip().lower()] = row['name']
    return {"id": id_lookup, "name": name_lookup}

def match_tags(tags, lookup):
    tags_set = set(tag.strip().lower() for tag in tags.split(',') if tag.strip())
    matched_ids = [lookup["id"][tag] for tag in tags_set if tag in lookup["id"]]
    matched_names = [lookup["name"][tag] for tag in tags_set if tag in lookup["name"]]
    return ', '.join(matched_ids), ', '.join(matched_names)

def fill_tactics_from_techniques(row, techniques_lookup, tactics_lookup, techniques_df):
    if not row.get("tactics_id") and row.get("techniques_id"):
        tactics_names = []
        for tech_id in row["techniques_id"].split(','):
            tech_id = tech_id.strip()
            if tech_id and tech_id.lower() in techniques_lookup["id"]:
                idx = techniques_df[techniques_df['ID'].str.lower() == tech_id.lower()].index
                if not idx.empty:
                    tactics = techniques_df.at[idx[0], 'tactics']
                    if pd.notna(tactics):
                        tactics_names += [t.strip() for t in tactics.split(',')]
        matched_ids, matched_names = match_tags(', '.join(tactics_names), tactics_lookup)
        row["tactics_id"] = matched_ids
        row["tactics_name"] = matched_names
    return row

def split_file_path(file_path):
    parts = file_path.parts
    type_folder = parts[0] if parts else ""
    datasource = str(Path(*parts[1:])) if len(parts) > 1 else ""
    return type_folder, datasource

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, help='Root directory containing YAML files')
    parser.add_argument('--tactics', required=True, help='Path to tactics.csv')
    parser.add_argument('--techniques', required=True, help='Path to techniques.csv')
    parser.add_argument('--output', required=True, help='Output CSV file path')
    parser.add_argument('--log', default='WARN', help='Logging level (DEBUG/INFO/WARN/ERROR)')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper(), None), format='%(levelname)s: %(message)s')

    tactics_df = load_csv(args.tactics)
    techniques_df = load_csv(args.techniques)
    tactics_lookup = build_lookup(tactics_df)
    techniques_lookup = build_lookup(techniques_df)
    columns = [
        "date", "modified", "Type", "Datasource", "tags", "original_tags",
        "tactics_id", "tactics_name", "techniques_id", "techniques_name",
        "logsource", "title", "description", "detection", "falsepositives",
        "fields", "level", "references", "File path", "file name"
    ]
    data_rows = []
    error_files = 0
    processed_files = 0
    root_dir = Path(args.root)

    yaml_files = list(root_dir.rglob('*.yml')) + list(root_dir.rglob('*.yaml'))
    for file_path in tqdm(yaml_files, desc="Processing YAMLs"):
        relative_path = file_path.relative_to(root_dir)
        row = {key: "" for key in columns}
        row["File path"] = str(relative_path.parent)
        row["file name"] = file_path.name
        row["Type"], row["Datasource"] = split_file_path(relative_path.parent)
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
                fields = content.get("fields", "")
                if isinstance(fields, list):
                    row["fields"] = ', '.join(fields)
                elif isinstance(fields, dict):
                    row["fields"] = format_tags(fields)
                else:
                    row["fields"] = format_tags(fields)
                row["level"] = content.get("level", "")
                refs = content.get("references", "")
                if isinstance(refs, list):
                    row["references"] = ', '.join(refs)
                elif isinstance(refs, dict):
                    row["references"] = format_tags(refs)
                else:
                    row["references"] = format_tags(refs)
                if row["tags"]:
                    row["tactics_id"], row["tactics_name"] = match_tags(row["tags"], tactics_lookup)
                    row["techniques_id"], row["techniques_name"] = match_tags(row["tags"], techniques_lookup)
                row = fill_tactics_from_techniques(row, techniques_lookup, tactics_lookup, techniques_df)
            processed_files += 1
        except Exception as e:
            logging.error(f"File error: {file_path}: {e}")
            error_files += 1
        data_rows.append(row)
    with open(args.output, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(data_rows)
    print(f"\nProcessed: {processed_files}, Errors: {error_files}, Output: {args.output}")

if __name__ == "__main__":
    main()
