# Use official lightweight Python image as base
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# Install essential system dependencies and Go
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    gcc \
    make \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Go (needed for subfinder, gau, urlfinder compilation)
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest

# Set working directory inside the container
WORKDIR /app

# Copy requirements file first to utilize Docker layer caching
COPY requirements.txt .

# Install Python dependencies and recon tools (dirsearch, waymore)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Expose the application port
EXPOSE 8003

# Run the FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
