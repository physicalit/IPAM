FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
# System deps for scanning
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
