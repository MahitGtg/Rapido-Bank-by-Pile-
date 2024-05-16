import os
import yara

def is_hidden(filepath):
    return os.path.basename(filepath).startswith('.')

def scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        hidden_matches = [match for match in matches if match.rule == "HiddenSensitiveFiles"]

        if matches:
            if is_hidden(file_path) or not hidden_matches:
                return matches
            else:
                # Remove HiddenSensitiveFile match if the file is not hidden
                return [match for match in matches if match.rule != "HiddenSensitiveFiles"]
    except yara.Error as e:
        print(f"Error scanning {file_path}: {e}")
    return []

def scan_directory(directory, rules):
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            matches = scan_file(file_path, rules)
            if matches:
                results[file_path] = [match.rule for match in matches]
    return results

def main():
    rules_path = 'rules.yar'  # Path to your YARA rules file
    target_directory = 'samples'    # Directory to scan

    try:
        rules = yara.compile(filepath=rules_path)
    except yara.SyntaxError as e:
        print(f"Error compiling YARA rules: {e}")
        return

    results = scan_directory(target_directory, rules)

    for file_path, rule_names in results.items():
        print(f"{file_path} - {rule_names}")

if __name__ == "__main__":
    main()
