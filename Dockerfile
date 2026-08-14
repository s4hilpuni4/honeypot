FROM python:3.9-slim

# Create a non-privileged system user/group for process isolation
RUN groupadd -g 10001 honeypot && \
    useradd -u 10001 -g honeypot -m -s /bin/bash honeypot

WORKDIR /app

# Copy only the honeypot daemon script
COPY honeypot.py /app/honeypot.py

# Create target log directories and configure ownership
RUN mkdir -p /var/log/honeypot && \
    touch /var/log/honeypot/honeypot.log && \
    chown -R honeypot:honeypot /var/log/honeypot /app

# Switch to the non-privileged user
USER honeypot

# Expose simulated SSH and HTTP service ports
EXPOSE 2222 8080

# Execute honeypot on container start
ENTRYPOINT ["python3", "honeypot.py"]
CMD ["--ssh-port", "2222", "--http-port", "8080", "--log-file", "/var/log/honeypot/honeypot.log"]
