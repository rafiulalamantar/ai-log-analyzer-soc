# One image for the API and the dashboard; docker-compose.yml picks the command.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ app/
COPY dashboard/ dashboard/
COPY data/samples/ data/samples/
COPY data/holdout/ data/holdout/

RUN useradd --create-home --uid 1000 soc
USER soc

EXPOSE 8000 8501
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
