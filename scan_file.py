
from pathlib import Path
import sys

import joblib
from security_rules import check_security

MODEL_PATH = Path("models/reposhield_model.joblib")


def scan_file(file_path):
    path = Path(file_path)

    # 1. Validate the file
    if not path.is_file():
        print(f"Error: File not found: {path}")
        return

    if path.suffix.lower() != ".py":
        print("Error: Please provide a Python (.py) file.")
        return

    try:
        source_code = path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        print(f"Error reading file: {error}")
        return

    if not source_code.strip():
        print("Error: The Python file is empty.")
        return

    if not MODEL_PATH.is_file():
        print(f"Error: Model not found: {MODEL_PATH}")
        return

    # 2. Run the ML model
    try:
        model = joblib.load(MODEL_PATH)
        prediction = int(model.predict([source_code])[0])
        probabilities = model.predict_proba([source_code])[0]
        confidence = float(probabilities[prediction]) * 100
    except Exception as error:
        print(f"Error running ML model: {error}")
        return

    # 3. Run rule-based checks
    findings = check_security(source_code)

    # 4. Display the report
    print("\n" + "=" * 45)
    print("          RepoShield Scan Report")
    print("=" * 45)

    print(f"File: {path.name}")

    if prediction == 1:
        print("ML Prediction: Potentially vulnerable")
    else:
        print("ML Prediction: Predicted non-vulnerable")

    print(f"Model confidence: {confidence:.2f}%")

    print("\n--- Rule-Based Security Checks ---")

    # These messages mean no security pattern was found,
    # or the source could not be analyzed.
    no_finding_messages = (
        "No matching risky patterns detected by these rules.",
        "No matching risky file-opening pattern detected.",
    )

    is_syntax_error = any(
        finding.startswith("Could not analyze:")
        for finding in findings
    )

    actual_findings = [
        finding
        for finding in findings
        if not finding.startswith(no_finding_messages)
        and not finding.startswith("Could not analyze:")
    ]

    if is_syntax_error:
        for finding in findings:
            print(f"- {finding}")
    elif actual_findings:
        for finding in actual_findings:
            print(f"- {finding}")
    else:
        print("- No matching risky patterns detected by these rules.")

    # 5. Overall assessment
    print("\n--- Overall Assessment ---")

    if is_syntax_error:
        print("Status: ANALYSIS INCOMPLETE")
        print("Reason: Python syntax could not be analyzed.")
    elif actual_findings:
        print("Status: REVIEW REQUIRED")
        print("Reason: One or more security patterns were flagged.")
    elif prediction == 1:
        print("Status: REVIEW REQUIRED")
        print("Reason: The ML model flagged this file.")
    else:
        print("Status: NO MATCHING ISSUES DETECTED")
        print("Warning: This does not guarantee the code is safe.")

    print("\nNote: ML predictions and security rules can be wrong.")
    print("Manually review findings before making security decisions.")
    print("=" * 45)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_file.py path\\to\\file.py")
    else:
        scan_file(sys.argv[1])
