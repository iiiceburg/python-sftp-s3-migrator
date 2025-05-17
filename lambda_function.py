import os
import logging
import tempfile
from typing import Optional, Union
import paramiko
import boto3
import magic
from botocore.exceptions import ClientError
from pathlib import Path
import json
import textwrap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SFTPToS3Sync:
    def __init__(self):
        # SFTP configuration
        self.sftp_host = os.environ['SFTP_HOST']
        self.sftp_port = int(os.environ.get('SFTP_PORT', 22))
        # Get credentials from Secrets Manager
        
        creds = self._get_secret_value(os.environ.get('SFTP_CREDENTIAL_SECRET_NAME'), parse_json=True)
        self.sftp_username = creds.get('username')
        self.sftp_password = creds.get('password')
        self.sftp_private_key = creds.get('sftp_private_key')
        logger.info(self.sftp_private_key)
        self.sftp_remote_path = os.environ['SFTP_REMOTE_PATH']

        # S3 configuration
        self.s3_bucket_name = os.environ['S3_BUCKET_NAME']
        self.s3_upload_path = os.environ['S3_UPLOAD_PATH'].rstrip('/')

        # Initialize connections
        self.sftp = None
        self.s3_client = None
        
        # Magic MIME type detector
        self.mime = magic.Magic(mime=True)


    def _get_secret_value(self, secret_name: str, parse_json=False) -> Optional[Union[str, dict]]:
        """
        Retrieve a secret from AWS Secrets Manager.

        Args:
            secret_name: Name of the secret to retrieve
            parse_json: If True, parse the secret string as JSON

        Returns:
            The secret value (str or dict)
        """
        if not secret_name:
            logger.debug("No secret name provided")
            return None

        try:
            logger.debug(f"Attempting to retrieve secret: {secret_name}")
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager')

            get_secret_value_response = client.get_secret_value(SecretId=secret_name)

            if 'SecretString' in get_secret_value_response:
                secret_string = get_secret_value_response['SecretString']
                logger.debug("Successfully retrieved secret")
                return json.loads(secret_string) if parse_json else secret_string
            else:
                logger.debug("Secret value not found in response")
                return None

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to retrieve secret '{secret_name}': {error_code} - {error_message}")
            raise

    def connect_sftp(self) -> None:
        """Establish SFTP connection using either password or private key authentication."""
        try:
            transport = paramiko.Transport((self.sftp_host, self.sftp_port))
            
            if self.sftp_private_key:
                logger.debug("Attempting private key authentication")
                try:
                    # Clean up escaped newlines and surrounding quotes
                    raw_key = self.sftp_private_key.strip('"\'').replace('\\n', '\n').strip()

                    # Ensure proper formatting
                    if "BEGIN RSA PRIVATE KEY" in raw_key and "END RSA PRIVATE KEY" in raw_key:
                        lines = raw_key.splitlines()

                        if len(lines) <= 3:
                            # It's likely a single-line key; reformat it
                            raw_key = raw_key.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "")
                            raw_key = raw_key.replace("\n", "").replace(" ", "").strip()

                            key_body = "\n".join(textwrap.wrap(raw_key, 64))
                            key_str = f"-----BEGIN RSA PRIVATE KEY-----\n{key_body}\n-----END RSA PRIVATE KEY-----\n"
                            logger.debug("Reformatted single-line private key")
                        else:
                            key_str = raw_key
                    else:
                        raise ValueError("Invalid private key format")
                    
                    # Save to temp file
                    key_file = tempfile.NamedTemporaryFile(delete=False)
                    key_file.write(key_str.encode())
                    key_file.close()
                    logger.debug("Private key written to temporary file")

                    try:
                        private_key = paramiko.RSAKey.from_private_key_file(key_file.name)
                        logger.debug("Successfully loaded private key")
                    except Exception as e:
                        logger.error(f"Failed to load private key: {str(e)}")
                        raise
                    finally:
                        os.unlink(key_file.name)

                    transport.connect(username=self.sftp_username, pkey=private_key)
                    logger.debug("Successfully authenticated with private key")
                except Exception as e:
                    logger.error(f"Private key authentication failed: {str(e)}")
                    raise
            else:
                logger.debug("No private key found, attempting password authentication")
                if not self.sftp_password:
                    raise ValueError("Neither private key nor password provided")
                transport.connect(username=self.sftp_username, password=self.sftp_password)
            
            self.sftp = paramiko.SFTPClient.from_transport(transport)
            logger.info(f"Successfully connected to SFTP server: {self.sftp_host}")
        
        except Exception as e:
            logger.error(f"Failed to connect to SFTP server: {str(e)}")
            raise

    def connect_s3(self) -> None:
        """Initialize S3 client and test bucket access."""
        try:
            session = boto3.Session()
            self.s3_client = session.client('s3')
            
            # Test bucket access by listing objects (with max 1 result)
            self.s3_client.list_objects_v2(Bucket=self.s3_bucket_name, MaxKeys=1)
            logger.info(f"Successfully connected to S3 bucket: {self.s3_bucket_name}")
        
        except Exception as e:
            logger.error(f"Failed to connect to S3: {str(e)}")
            raise

    def get_mime_type(self, file_path: str) -> str:
        """Determine MIME type of a file."""
        try:
            return self.mime.from_file(file_path)
        except Exception:
            # Default to binary/octet-stream if unable to determine
            return 'application/octet-stream'

    def upload_to_s3(self, local_path: str, remote_path: str) -> None:
        """Upload a file to S3 with proper MIME type."""
        try:
            mime_type = self.get_mime_type(local_path)
            self.s3_client.upload_file(
                local_path,
                self.s3_bucket_name,
                remote_path,
                ExtraArgs={
                    'ContentType': mime_type
                }
            )
            logger.info(f"Successfully uploaded to S3: {remote_path}")
        except Exception as e:
            logger.error(f"Failed to upload {remote_path} to S3: {str(e)}")
            raise

    def process_sftp_path(self, remote_path: str) -> None:
        """Recursively process SFTP path and upload files to S3."""
        try:
            # List directory contents
            for entry in self.sftp.listdir_attr(remote_path):
                full_remote_path = f"{remote_path}/{entry.filename}"
                
                if self.should_skip_file(entry.filename):
                    continue

                if self.is_directory(entry):
                    # Recursively process directory
                    self.process_sftp_path(full_remote_path)
                else:
                    # Process file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        # Download file from SFTP
                        self.sftp.get(full_remote_path, temp_file.name)
                        
                        # Calculate S3 path
                        relative_path = full_remote_path.replace(self.sftp_remote_path, '').lstrip('/')
                        s3_path = f"{self.s3_upload_path}/{relative_path}"
                        
                        # Upload to S3
                        self.upload_to_s3(temp_file.name, s3_path)
                        
                        # Clean up temp file
                        os.unlink(temp_file.name)

        except Exception as e:
            logger.error(f"Error processing path {remote_path}: {str(e)}")
            raise

    def is_directory(self, entry: paramiko.SFTPAttributes) -> bool:
        """Check if SFTP entry is a directory."""
        return entry.st_mode & 0o170000 == 0o040000

    def should_skip_file(self, filename: str) -> bool:
        """Check if file should be skipped (e.g., hidden files)."""
        return filename.startswith('.')

    def cleanup(self) -> None:
        """Clean up SFTP connection."""
        if self.sftp:
            transport = self.sftp.get_channel().get_transport()
            self.sftp.close()
            if transport:
                transport.close()

def lambda_handler(event, context):
    """AWS Lambda handler function."""
    try:
        sync = SFTPToS3Sync()
        
        # Establish connections
        sync.connect_sftp()
        sync.connect_s3()
        
        # Process files
        sync.process_sftp_path(sync.sftp_remote_path)
        
        # Cleanup
        sync.cleanup()
        
        return {
            'statusCode': 200,
            'body': 'Successfully synced SFTP to S3'
        }
    
    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': f'Error: {str(e)}'
        }

if __name__ == '__main__':
    # For local testing
    lambda_handler(None, None) 