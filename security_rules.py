
import ast
import re


def check_security(source_code):
    findings = []

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return ["Could not analyze: invalid Python syntax."]

    concatenated_variables = set()

    # Rule 1: Find variables assigned using string concatenation.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if (
                isinstance(node.value, ast.BinOp)
                and isinstance(node.value.op, ast.Add)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        concatenated_variables.add(target.id)

    # Rule 2: Check for potentially risky function calls.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        function_name = ""

        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr

        # Dynamic code execution
        if function_name in {"eval", "exec"}:
            findings.append(
                f"Line {node.lineno}: {function_name}() can execute "
                "dynamic code. Review whether its input is trusted."
            )

        # Shell command execution
        if function_name == "system":
            findings.append(
                f"Line {node.lineno}: system() may execute an operating "
                "system command. Review how the command is constructed."
            )

        if function_name in {"run", "Popen", "call", "check_output"}:
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "subprocess":
                        findings.append(
                            f"Line {node.lineno}: subprocess.{function_name}() "
                            "can launch a process. Review command arguments "
                            "and avoid unsafe shell execution."
                        )

        # Unsafe deserialization
        if function_name == "loads":
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "pickle":
                        findings.append(
                            f"Line {node.lineno}: pickle.loads() can execute "
                            "code during deserialization. Only load trusted data."
                        )

        # File paths built using string concatenation
        if function_name == "open" and node.args:
            filename_arg = node.args[0]

            risky_path = (
                isinstance(filename_arg, ast.BinOp)
                and isinstance(filename_arg.op, ast.Add)
            ) or (
                isinstance(filename_arg, ast.Name)
                and filename_arg.id in concatenated_variables
            )

            if risky_path:
                findings.append(
                    f"Line {node.lineno}: File path may use string "
                    "concatenation. Validate user input and restrict "
                    "access to the intended directory."
                )

    # Rule 3: Look for possible hardcoded secrets.
    secret_pattern = re.compile(
        r"""(?i)\b(password|passwd|secret|api_key|apikey|access_token)"""
        r"""\b\s*=\s*["'][^"']{4,}["']"""
    )

    for line_number, line in enumerate(source_code.splitlines(), start=1):
        if secret_pattern.search(line):
            findings.append(
                f"Line {line_number}: Possible hardcoded secret. "
                "Check whether this value is sensitive."
            )

    # Remove duplicate messages while preserving order.
    findings = list(dict.fromkeys(findings))

    if not findings:
        findings.append(
            "No matching risky patterns detected by these rules."
        )

    return findings
