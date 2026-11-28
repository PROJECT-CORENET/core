FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl ffmpeg librlottie0-1 python3-flask python3-pil gunicorn && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY service.py serve-tls.sh ./
RUN install -d -m 0700 -o nobody -g nogroup /app/tls
USER nobody
# CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "75", "service:app"]
CMD ["sh", "./serve-tls.sh"]
