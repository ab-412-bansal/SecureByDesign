FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN --network=host pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt
COPY . /app
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]