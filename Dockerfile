# Step 1: Use an official Python runtime as a base image
FROM python:3.9-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the current directory (all files) into the container
COPY . /app

# Step 4: Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Expose port 8000 to allow traffic through that port
EXPOSE 8000

# Step 6: Define the command to run your Flask app
CMD ["python", "app.py"]
