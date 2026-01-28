# Dockerfile for Application Container
# This container runs the HTTP server and client

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Make scripts executable
RUN chmod +x src/application/server.py src/application/client.py

# Create output directory
RUN mkdir -p /output

# Expose HTTP server port
EXPOSE 8080

# Default command (run server)
CMD ["python3", "src/application/server.py", "--host", "0.0.0.0", "--port", "8080"]

# Alternative commands:
# Server: python3 src/application/server.py
# Client: python3 src/application/client.py --url http://server:8080
