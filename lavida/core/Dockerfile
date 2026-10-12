FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AIAP_DATA_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home aiap && mkdir -p /data && chown aiap:aiap /data && chmod 700 /data
COPY aiap_core ./aiap_core
COPY profile ./profile
USER 10001:10001
EXPOSE 8042
ENTRYPOINT ["python", "-m", "aiap_core"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8042"]
