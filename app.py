
from pathlib import Path
from io import BytesIO

import joblib
from flask import Flask, render_template, request, send_file
from security_rules import check_security

app = Flask(__name__)

MODEL_PATH = Path("models/reposhield_model.joblib")
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def analyze_source(source_code):
    """Run ML prediction and rule-based security checks."""
    model = joblib.load(MODEL_PATH)

    prediction = int(model.predict([source_code])[0])
    probabilities = model.predict_proba([source_code])[0]
    confidence = float(probabilities[prediction]) * 100

    findings = check_security(source_code)

    syntax_error = any(
        item.startswith("Could not analyze:")
        for item in findings
    )

    no_finding_messages = (
        "No matching risky patterns detected by these rules.",
        "No matching risky file-opening pattern detected.",
    )

    actual_findings = [
        item for item in findings
        if not item.startswith(no_finding_messages)
        and not item.startswith("Could not analyze:")
    ]

    if syntax_error:
        status = "ANALYSIS INCOMPLETE"
    elif actual_findings or prediction == 1:
        status = "REVIEW REQUIRED"
    else:
        status = "NO MATCHING ISSUES DETECTED"

    return {
        "prediction": (
            "Potentially vulnerable"
            if prediction == 1
            else "Predicted non-vulnerable"
        ),
        "confidence": round(confidence, 2),
        "findings": findings,
        "status": status,
    }


def create_text_report(filename, report):
    """Create a downloadable plain-text scan report."""
    lines = [
        "=" * 50,
        "                 RepoShield Scan Report",
        "=" * 50,
        f"File: {filename}",
        f"ML Prediction: {report['prediction']}",
        f"Model confidence: {report['confidence']:.2f}%",
        f"Overall status: {report['status']}",
        "",
        "--- Rule-Based Security Checks ---",
    ]

    for finding in report["findings"]:
        lines.append(f"- {finding}")

    lines.extend([
        "",
        "--- Important Notice ---",
        "This report is an automated preliminary analysis.",
        "The model and security rules can make mistakes.",
        "A flagged pattern does not always prove a vulnerability.",
        "No detected pattern does not guarantee that code is safe.",
        "Review the source code manually before making decisions.",
        "=" * 50,
    ])

    return "\n".join(lines)


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    filename = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file is None or not uploaded_file.filename:
            error = "Please choose a Python file."

        elif Path(uploaded_file.filename).suffix.lower() != ".py":
            error = "Only .py files are supported."

        elif not MODEL_PATH.is_file():
            error = "Trained model not found. Check the models folder."

        else:
            try:
                raw_data = uploaded_file.stream.read(MAX_FILE_SIZE + 1)

                if len(raw_data) > MAX_FILE_SIZE:
                    error = "File is too large. Maximum size is 1 MB."

                else:
                    source_code = raw_data.decode(
                        "utf-8",
                        errors="replace",
                    )

                    if not source_code.strip():
                        error = "The uploaded file is empty."

                    else:
                        filename = Path(uploaded_file.filename).name
                        report = analyze_source(source_code)

                        if request.form.get("action") == "download":
                            report_text = create_text_report(
                                filename,
                                report,
                            )

                            report_bytes = BytesIO(
                                report_text.encode("utf-8")
                            )
                            report_bytes.seek(0)

                            download_name = (
                                f"{Path(filename).stem}_reposhield_report.txt"
                            )

                            return send_file(
                                report_bytes,
                                mimetype="text/plain; charset=utf-8",
                                as_attachment=True,
                                download_name=download_name,
                            )

            except Exception as exc:
                app.logger.exception("File analysis failed")
                error = f"Analysis failed: {type(exc).__name__}."

    return render_template(
        "index.html",
        report=report,
        filename=filename,
        error=error,
    )


@app.errorhandler(413)
def file_too_large(_error):
    return render_template(
        "index.html",
        report=None,
        filename=None,
        error="File is too large. Maximum size is 1 MB.",
    ), 413


if __name__ == "__main__":
    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000,
    )
