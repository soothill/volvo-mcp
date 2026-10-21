FROM python:3.12-slim
RUN useradd -m appuser
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
RUN mkdir -p /data && chown appuser /data
USER appuser
ENV MCP_HOST=0.0.0.0 MCP_PORT=8090 VOLVO_TOKEN_PATH=/data/volvo-token.json
EXPOSE 8090
CMD ["python", "server.py"]
