# Use official lightweight Python image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Install AWS CLI and boto3
RUN apt-get update && \
    apt-get install -y curl unzip && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws && \
    apt-get clean

RUN pip install boto3 --no-cache-dir

# Copy auditors and wrapper script into the container
COPY auditors/ ./auditors/
COPY run_audit.sh .

# Create reports directory inside container
RUN mkdir -p reports

# Make wrapper executable
RUN chmod +x run_audit.sh

# Default command — runs the full audit
CMD ["bash", "run_audit.sh"]
