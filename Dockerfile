# Use official Python runtime with Apify base image
FROM apify/actor-python:3.11

# Set working directory
WORKDIR /usr/src/app

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . ./

# Specify how to run the actor
CMD python -m src