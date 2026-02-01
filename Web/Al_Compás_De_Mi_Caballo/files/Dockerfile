FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY data/ data/

# Expose port
EXPOSE 6002

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:6002", "--workers", "2", "app:app"]
