"""
Path Traversal vulnerability examples for E2E testing
These functions demonstrate insecure file path handling
"""

import os


def read_user_file(filename):
    """
    VULNERABLE: Path traversal - no validation on filename
    User could provide "../../../etc/passwd" to access sensitive files
    """
    base_path = "/var/www/uploads/"
    # VULNERABLE: Direct concatenation without path validation
    file_path = base_path + filename

    with open(file_path, 'r') as f:
        return f.read()


def download_file(user_id, filename):
    """
    VULNERABLE: Path traversal via string formatting
    User could provide "../../etc/shadow" in filename
    """
    # VULNERABLE: String formatting without sanitization
    path = f"/home/users/{user_id}/documents/{filename}"

    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    return None


def load_template(template_name):
    """
    VULNERABLE: Path traversal with os.path.join
    Even os.path.join can be vulnerable if not validated
    """
    template_dir = "/app/templates/"
    # VULNERABLE: Absolute paths in template_name can bypass join
    full_path = os.path.join(template_dir, template_name)

    with open(full_path, 'r') as f:
        return f.read()


def delete_user_file(username, filename):
    """
    VULNERABLE: Path traversal in file deletion
    Could delete system files if not validated
    """
    # VULNERABLE: No path validation before deletion
    file_path = f"/tmp/user_files/{username}/{filename}"

    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    return False


def write_log(log_filename, message):
    """
    VULNERABLE: Path traversal in write operations
    User could overwrite system files
    """
    log_dir = "/var/log/app/"
    # VULNERABLE: Concatenation without validation
    log_path = log_dir + log_filename

    with open(log_path, 'a') as f:
        f.write(message + '\n')


# Example of how these could be exploited
if __name__ == "__main__":
    # Attacker could read /etc/passwd
    malicious_filename = "../../../../etc/passwd"
    content = read_user_file(malicious_filename)

    # Attacker could access other users' files
    malicious_path = "../../../other_user/secrets.txt"
    data = download_file("user123", malicious_path)

    # Attacker could load arbitrary system files
    malicious_template = "/etc/shadow"
    template = load_template(malicious_template)
