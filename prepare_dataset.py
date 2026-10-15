
import csv
import io
import zipfile
from pathlib import Path
from urllib.parse import unquote

import pandas as pd

# Paths
zip_path = Path.home() / "Downloads" / "BenchmarkPython-main.zip"
output_dir = Path("data")
output_csv = output_dir / "reposhield_dataset.csv"

output_dir.mkdir(exist_ok=True)

rows = []

with zipfile.ZipFile(zip_path, "r") as archive:
    # Read expected labels directly from the ZIP
    label_file = "BenchmarkPython-main/expectedresults-0.1.csv"

    with archive.open(label_file) as file:
        content = io.TextIOWrapper(file, encoding="utf-8")
        reader = csv.reader(content)

        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue

            test_name = row[0].strip()
            category = row[1].strip()
            label = row[2].strip().lower()
            cwe = row[3].strip()

            if label not in {"true", "false"}:
                continue

            source_path = (
                f"BenchmarkPython-main/testcode/{test_name}.py"
            )

            try:
                with archive.open(source_path) as source_file:
                    source_code = source_file.read().decode("utf-8")
            except KeyError:
                print(f"Source file missing: {test_name}")
                continue

            rows.append({
                "test_name": test_name,
                "category": category,
                "cwe": cwe,
                "label": int(label == "true"),
                "source_code": source_code,
            })

df = pd.DataFrame(rows)
df.to_csv(output_csv, index=False, encoding="utf-8")

print(f"Dataset saved to: {output_csv}")
print(f"Total labeled samples: {len(df)}")

if not df.empty:
    print("\nLabel counts:")
    print(df["label"].value_counts().sort_index())
    print("\nFirst three samples:")
    print(df[["test_name", "category", "label"]].head(3))
