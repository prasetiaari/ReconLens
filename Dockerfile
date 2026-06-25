# Stage 1: Build/compile Go security tools
FROM golang:1.24-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev wget unzip

# Set environment variables for static linking
ENV CGO_ENABLED=0

# Compile Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/LukaSikic/subzy@latest \
    && go install -v github.com/haccer/subjack@latest

# Download and extract precompiled OWASP Amass to save memory and compile time
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then AMASS_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then AMASS_ARCH="arm64"; \
    else AMASS_ARCH="amd64"; fi && \
    wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_${AMASS_ARCH}.zip \
    && unzip -q amass_Linux_${AMASS_ARCH}.zip \
    && mv amass_Linux_${AMASS_ARCH}/amass /go/bin/amass \
    && rm -rf amass_Linux_${AMASS_ARCH}*

# Download and install Findomain precompiled binary
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then FINDOMAIN_ARCH="linux"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then FINDOMAIN_ARCH="aarch64"; \
    else FINDOMAIN_ARCH="linux"; fi && \
    wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-${FINDOMAIN_ARCH}.zip \
    && unzip -q findomain-${FINDOMAIN_ARCH}.zip \
    && chmod +x findomain \
    && mv findomain /go/bin/findomain \
    && rm -rf findomain*

# Stage 2: Final lightweight runner image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install runtime system dependencies (e.g., git for dirsearch/waymore, curl, wget, ca-certificates, procps iputils-ping)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ca-certificates \
    procps iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Go binaries from the builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/gau /usr/local/bin/gau
COPY --from=go-builder /go/bin/urlfinder /usr/local/bin/urlfinder
COPY --from=go-builder /go/bin/amass /usr/local/bin/amass
COPY --from=go-builder /go/bin/findomain /usr/local/bin/findomain
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/subzy /usr/local/bin/subzy
COPY --from=go-builder /go/bin/subjack /usr/local/bin/subjack

# Set working directory inside the container
WORKDIR /app

# Create symbolic link so python -m ReconLens works seamlessly inside the container
RUN ln -s /app /ReconLens

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
