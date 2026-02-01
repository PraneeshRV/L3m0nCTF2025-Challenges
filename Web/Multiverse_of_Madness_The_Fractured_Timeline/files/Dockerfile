FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m ctf
USER ctf

EXPOSE 5000
CMD ["python", "app.py"]
