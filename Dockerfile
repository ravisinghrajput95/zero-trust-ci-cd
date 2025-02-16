# Use a minimal and secure base image
FROM python:3.11-slim

# Set a working directory
WORKDIR /app

# Copy only the necessary files
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application files
COPY app.py ./

# Run as a non-root user for security
RUN useradd -m flaskuser
USER flaskuser

# Expose the application port
EXPOSE 5000

# Set the command to run the application
CMD ["python", "app.py"]