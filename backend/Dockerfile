FROM python:3.12-slim

WORKDIR /app

# Install dependencies against a placeholder package so this layer stays cached
# when application code changes. The real app/ is copied over it below.
COPY pyproject.toml ./
RUN mkdir -p app && touch app/__init__.py && pip install --no-cache-dir -e ".[dev]"

COPY app ./app
COPY tests ./tests
COPY test.sh ./
RUN chmod +x test.sh

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
