🐞 BugTracker+ – Issue Tracking Web App
BugTracker+ is a lightweight, full-stack bug tracking system designed for internal software teams to report, update, and manage issues efficiently.

🌐 Live Demo
👉 https://bugtracker-4qzo.onrender.com

🛠 Tech Stack
Frontend: HTML, Bootstrap
Backend: Flask (Python)
Database: MongoDB (Atlas)
Hosting: Render

🔐 Features

Secure Login/Registration (admin & developer roles)

Role-based access

  Admins can delete bugs
  
  Developers can update bug status
  
Filter bugs by status (Open/In Progress/Resolved)

RESTful API structure and modular codebase

🚀 How to Run Locally

1.**Clone the repo**  
   ```bash

git clone https://github.com/SNidhi2004/BugTracker.git

cd BugTracker

2.**Create virtual environment & install requirements**  
   ```bash

python -m venv venv

venv\Scripts\activate   # or source venv/bin/activate on Linux/Mac

pip install -r requirements.txt

3.Configure MongoDB

Create a .env file and add your Mongo URI:

MONGO_URI=mongodb+srv://<username>:<password>@<cluster-url>/bugtracker

SECRET_KEY=your_secret_key

4.Run the app

python app.py

Then open http://localhost:5000
