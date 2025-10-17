# Use an official Python runtime as a parent image
FROM python:3.10-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Install tshark and GUI-related system libraries
RUN apt-get update && apt-get install -y \
    tshark \
    libgl1-mesa-glx \
    libegl1-mesa \
    libxkbcommon-x11-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's source code
COPY . .

# Set the command to run the application
CMD ["python3", "domain_sentinel.py"]
