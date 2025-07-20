# Use Python 3.11 slim image for a smaller footprint
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies from requirements.txt
# --no-cache-dir: Prevents pip from storing cache, reducing image size
# -r: Install from the specified requirements file
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code (including main.py) into the container
COPY . .

# Command to run the FastAPI application using Uvicorn
# 0.0.0.0: Binds to all network interfaces, making the app accessible from outside the container
# 80: The port the application will listen on
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]