FROM registry.access.redhat.com/ubi9/python-312:latest AS builder

WORKDIR /docs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mkdocs.yml .
COPY docs/ docs/

RUN git init && git add -A && git commit -m "build" --allow-empty && \
    ENABLED_HTMLPROOFER=false mkdocs build --strict

FROM registry.access.redhat.com/ubi9/httpd-24:latest

COPY --from=builder /docs/site/ /var/www/html/

EXPOSE 8080

CMD ["httpd", "-D", "FOREGROUND"]
