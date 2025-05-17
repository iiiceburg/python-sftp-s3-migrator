# 🚀 SFTP to S3 Sync – AWS Lambda Function

This AWS Lambda function syncs files and folders from an SFTP server to an Amazon S3 bucket. It supports both **password-based** and **private key-based** authentication via AWS Secrets Manager, and is designed for reliable, recursive transfers while preserving the directory structure.

---

## 🔧 Features

- 🔁 Recursive file and folder copy from SFTP to S3
- 🔐 Supports authentication via AWS Secrets Manager
- 🧠 Automatic MIME type detection
- 📁 Preserves remote directory structure in S3
- ⚠️ Robust error handling and logging
- ⚡ Optimized for AWS Lambda execution

---

## 🌎 Environment Variables

### 🔐 SFTP Configuration

| Variable                      | Description                                                                                                   |
|-------------------------------|---------------------------------------------------------------------------------------------------------------|
| `SFTP_HOST`                   | Hostname or IP address of the SFTP server                                                                     |
| `SFTP_CREDENTIAL_SECRET_NAME` | Name of the AWS Secrets Manager secret containing SFTP credentials in JSON format (see below)                 |
| `SFTP_REMOTE_PATH`            | Remote directory path on the SFTP server to copy from                                                         |

> 💡 **Secrets Manager Format Example:**
> ```json
> {
>   "username": "your-username",
>   "password": "your-password"
> }
> ```
> Or for private key authentication:
> ```json
> {
>   "username": "your-username",
>   "private_key": "-----BEGIN PRIVATE KEY-----\n..."
> }
> ```

### ☁️ S3 Configuration

| Variable           | Description                                               |
|--------------------|-----------------------------------------------------------|
| `S3_BUCKET_NAME`   | Name of the target S3 bucket                              |
| `S3_UPLOAD_PATH`   | Prefix path within the S3 bucket to upload the files into |

---

## 🚀 AWS Lambda Deployment

1. **Install dependencies locally**:
   ```bash
   pip install -r requirements.txt -t .
   ```

2. **Create deployment package**:
   ```bash
   zip -r lambda-deployment.zip . -x "*.git*" "*.venv*"
   ```

3. **Configure Lambda function**:
   - **Runtime**: Python 3.9+
   - **Handler**: `sftp_to_s3_sync.lambda_handler`
   - **Memory**: 512MB (recommended)
   - **Timeout**: 5+ minutes (adjust based on file volume/size)

4. **Set environment variables** in the Lambda console.

5. **Attach an IAM Role** with:
   - `s3:PutObject` permission to the target bucket
   - `secretsmanager:GetSecretValue` permission
   - `logs:*` for CloudWatch logging

6. **Schedule the function with EventBridge (optional)**:
   ```bash
   # Example: Run daily at 1 AM UTC
   cron(0 1 * * ? *)
   ```

---

## 🧪 Local Testing

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set required environment variables**:
   ```bash
   export SFTP_HOST="your-sftp-host"
   export SFTP_CREDENTIAL_SECRET_NAME="your-secret-name"
   export SFTP_REMOTE_PATH="/remote/path"
   export S3_BUCKET_NAME="your-s3-bucket"
   export S3_UPLOAD_PATH="upload/"
   ```

3. **Run the script**:
   ```bash
   python sftp_to_s3_sync.py
   ```

> 🔐 For local testing with secrets, you can use a `.env` file or mock `boto3` calls to return dummy credentials.

---

## ❗ Error Handling

The script includes comprehensive error handling for:

- 🔌 SFTP connection issues
- 🔑 Invalid credentials or Secrets Manager access
- 🚫 S3 permission or transfer errors
- 📂 Invalid paths or file system errors

Errors are logged to **CloudWatch Logs** when running in Lambda.

---

## 📦 Building Deployment Package (for ARM64/Graviton)

If targeting the `arm64` architecture on Lambda, use the following build process:

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Create a package directory
mkdir -p package

# Install dependencies for ARM64 platform
pip install     --platform manylinux2014_aarch64     --target ./package     --implementation cp     --python-version 3.13     --only-binary=:all:     --upgrade     -r requirements.txt

# Copy your Lambda handler
cp sftp_to_s3_sync.py package/

# Create ZIP package
cd package
zip -r ../lambda-deployment.zip .
cd ..

# Clean up
rm -rf package
deactivate
```

---

## ✅ Notes

- Ensure the secret in AWS Secrets Manager uses plaintext (not binary) format.
- For production, use AWS Parameter Store or Secrets Manager with encryption and access control.

---

Let me know if you'd like to include architecture diagrams, badges, or GitHub Actions in this README as well.