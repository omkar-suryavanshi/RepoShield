
# 🛡️ RepoShield

### ML-Powered Python Source Code Security Scanner

RepoShield is a Python-based security analysis tool that combines machine learning with rule-based checks to identify potentially risky patterns in Python source code.

It provides a simple web interface where users can upload a Python file, view the analysis results, and download a scan report.

> **Disclaimer:** RepoShield is an educational security analysis project. Its predictions are not proof that code is vulnerable or safe.

---

## ✨ Features

- **Machine Learning Detection:** Uses a trained scikit-learn model to classify source code as potentially vulnerable or non-vulnerable.
- **Rule-Based Analysis:** Uses Python's Abstract Syntax Tree (AST) and pattern matching to flag selected risky coding patterns.
- **Web Interface:** Upload and analyze Python files through a Flask application.
- **Downloadable Reports:** Export scan results as plain-text reports.
- **Input Validation:** Accepts Python files and limits uploads to 1 MB.
- **Local Processing:** Runs the model locally without requiring an external AI API.

## 🧠 How It Works

1. The user uploads a Python source file.
2. RepoShield reads the source code without executing the uploaded file.
3. A TF-IDF character n-gram representation is processed by a Logistic Regression model.
4. Rule-based checks inspect selected function calls, file-path construction, and possible hardcoded secrets.
5. The application combines the results into a scan report.
6. The user can view the report in the browser or download it.

## 🛠️ Technologies Used

- Python
- scikit-learn
- pandas
- Flask
- Joblib
- Abstract Syntax Trees (`ast`)
- Regular Expressions
- HTML and CSS
- TF-IDF Vectorization
- Logistic Regression

## 📁 Project Structure

```text
RepoShield/
├── app.py
├── train_model.py
├── evaluate_model.py
├── security_rules.py
├── scan_file.py
├── data/
│   └── reposhield_dataset.csv
├── models/
│   └── reposhield_model.joblib
├── templates/
│   └── index.html
├── example.py
├── safe_example.py
├── dynamic_code.py
├── security_test.py
└── README.md
```

*This structure describes the current project layout. Update it if your files differ.*

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd RepoShield
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual repository URL.

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install pandas scikit-learn matplotlib joblib flask
```

### 4. Prepare the dataset and train the model

Ensure the dataset is available at:

```text
data/reposhield_dataset.csv
```

Then run:

```bash
python train_model.py
```

This should create the trained model under the `models/` directory.

### 5. Run the web application

```bash
python app.py
```

Open this address in your browser:

```text
http://127.0.0.1:5000
```

Upload a `.py` file to start scanning.

## 📊 Initial Model Evaluation

The initial model evaluation on a random train/test split produced these results:

| Metric | Initial result |
|---|---:|
| Accuracy | 78.46% |
| Vulnerable-class precision | 68.69% |
| Vulnerable-class recall | 75.56% |
| Vulnerable-class F1-score | 72% |

The initial test set contained 246 samples, including 90 labeled vulnerable samples.

These results are a baseline, not proof of performance on unseen real-world repositories. Similar examples in the dataset may make a random split easier than a truly independent evaluation.

Further testing on separate projects and datasets is needed.

## 🔎 Security Checks

The current rule-based checks include selected patterns involving:

- Dynamic code execution through `eval()` and `exec()`
- Potentially risky operating-system and subprocess commands
- Deserialization through `pickle.loads()`
- File paths built using string concatenation
- Possible hardcoded secrets

These checks are heuristic. They do not provide complete data-flow analysis and may produce false positives or miss vulnerabilities.

## ⚠️ Limitations

- Only Python source files are supported.
- The ML model can misclassify both safe and vulnerable code.
- Model confidence is not the probability that a real vulnerability exists.
- Rule-based checks cover only a limited set of patterns.
- The application does not execute or dynamically test uploaded code.
- Results require human review.
- The Flask development server is intended for local development, not public production deployment.

## 🚀 Future Improvements

- Evaluate against independent, unseen source-code datasets.
- Add more security rules and severity levels.
- Improve detection of user-input flows and unsafe sinks.
- Add scan history and structured report exports.
- Compare additional machine learning models.
- Add automated tests and continuous integration.
- Prepare a production deployment configuration.

## 👨‍💻 Author

**Omkar Suryavanshi**

B.Tech Computer Science and Engineering

## 📄 License

Add a license file before distributing this project publicly. Choose a license that fits your intended use and any dataset or dependency requirements.
