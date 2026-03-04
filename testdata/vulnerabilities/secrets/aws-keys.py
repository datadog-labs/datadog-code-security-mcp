"""
Hardcoded AWS credentials - SECURITY VULNERABILITY
These are example credentials for E2E testing secrets detection
"""

import boto3

# VULNERABLE: Hardcoded AWS access key ID
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# VULNERABLE: Hardcoded AWS secret access key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: Hardcoded AWS session token
AWS_SESSION_TOKEN = "FwoGZXIvYXdzEBQaDKExampleSessionToken1234567890abcdefghijklmnopqrstuvwxyz"

# VULNERABLE: AWS credentials in configuration
aws_config = {
    'access_key': 'AKIAI44QH8DHBEXAMPLE',
    'secret_key': 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
    'region': 'us-east-1'
}


class AWSClient:
    """VULNERABLE: AWS client with hardcoded credentials"""

    def __init__(self):
        # VULNERABLE: Hardcoded credentials in initialization
        self.access_key = "AKIAJT5IQEXAMPLEKEY"
        self.secret_key = "1234567890abcdefghijklmnopqrstuvEXAMPLE"
        self.region = "us-west-2"

    def connect(self):
        """Connect to AWS using hardcoded credentials"""
        # VULNERABLE: Creating boto3 client with hardcoded creds
        client = boto3.client(
            's3',
            aws_access_key_id="AKIAIMEXAMPLEKEYID",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
            region_name=self.region
        )
        return client


def upload_to_s3(file_path):
    """VULNERABLE: S3 upload with hardcoded credentials"""
    # VULNERABLE: Inline credentials
    s3 = boto3.client(
        's3',
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    )

    bucket = 'my-bucket'
    s3.upload_file(file_path, bucket, 'uploaded-file.txt')


# VULNERABLE: Multiple credentials in comments
# Production AWS Key: AKIAJ3EXAMPLEPRODUCTION
# Backup access key: AKIAJ4EXAMPLEBACKUPKEY
# Legacy secret: abc123def456ghi789jklEXAMPLESECRET

if __name__ == "__main__":
    client = AWSClient()
    client.connect()
