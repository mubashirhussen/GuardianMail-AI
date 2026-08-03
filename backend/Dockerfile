FROM python:3.12-slim

WORKDIR /workspace

# Install system dependencies if needed (e.g. build-essential, git, libmagic)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies list
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create a non-privileged user to run the app
RUN groupadd -g 10001 appgroup && \
    useradd -r -u 10001 -g appgroup appuser

# Change ownership of the workspace directory
RUN chown -R appuser:appgroup /workspace

# Switch to non-root user
USER appuser

EXPOSE 8000

# Run FastAPI app by default
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
