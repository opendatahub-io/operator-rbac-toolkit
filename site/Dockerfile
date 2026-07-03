FROM registry.access.redhat.com/ubi9/python-312:latest AS builder

USER 0
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mkdocs.yml .
COPY docs/ docs/

RUN git config --global user.email "build@localhost" && \
    git config --global user.name "build" && \
    git init && git add -A && git commit -m "build" && \
    mkdocs build

FROM registry.access.redhat.com/ubi9/httpd-24:latest

COPY --from=builder /build/site/ /var/www/html/

EXPOSE 8080

CMD ["httpd", "-D", "FOREGROUND"]
