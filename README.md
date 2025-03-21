﻿# Hospital Management System

A web-based Hospital Management System built using **Flask**, **SQLAlchemy**, and **Bootstrap**. This system allows users to register, log in, and book appointments with doctors. It also provides a dashboard to view and manage appointments.

---

## Features

- **User Authentication**:
  - Register new users.
  - Log in and log out functionality.
- **Appointment Booking**:
  - Book appointments with a doctor by specifying the doctor's name, date, and time.
  - View all booked appointments in the dashboard.
- **Dashboard**:
  - Display a list of all appointments for the logged-in user.
  - Provide a form to book new appointments.
- **Flash Messages**:
  - Success and error messages for user actions (e.g., appointment booked successfully).

---

## Technologies Used

- **Backend**:
  - Flask (Python web framework)
  - Flask-SQLAlchemy (ORM for database management)
  - Flask-Login (User authentication)
  - Flask-WTF (Form handling)
- **Frontend**:
  - HTML, CSS, Bootstrap (Responsive UI)
- **Database**:
  - SQLite (Lightweight database for development)

---

## Prerequisites

Before running the project, ensure you have the following installed:

- Python 3.x
- Pip (Python package manager)

---

## Setup Instructions

### 1. Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/arsusan/Hospital_Managemet_System.git
cd Hospital_Managemet_System
```

### 2. Create a Virtual Environment

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 4. Initialize the Database

Run the following command to create the database and tables:

```bash
python -c "from app import app, db; with app.app_context(): db.create_all()"
```

### 5. Run the Application

Start the Flask development server:

```bash
python app.py
```

The application will be available at:

```
http://127.0.0.1:5000/
```

---

## Usage

1. **Register a New User**:

   - Navigate to the registration page (`/register`).
   - Fill out the form with your username, email, and password.
   - Click "Sign Up" to create an account.

2. **Log In**:

   - Navigate to the login page (`/login`).
   - Enter your username and password.
   - Click "Login" to access the dashboard.

3. **Book an Appointment**:

   - On the dashboard, fill out the appointment booking form.
   - Enter the doctor's name, date, and time.
   - Click "Book Appointment" to save the appointment.

4. **View Appointments**:

   - All booked appointments will be displayed in the "Your Appointments" table on the dashboard.

5. **Log Out**:
   - Click "Logout" in the navigation bar to log out of the system.

---

## Project Structure

```
Hospital_Managemet_System/
├── app.py                  # Main Flask application
├── requirements.txt        # List of dependencies
├── README.md               # Project documentation
├── templates/              # HTML templates
│   ├── base.html           # Base template
│   ├── home.html           # Home page
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   └── dashboard.html      # Dashboard page
└── static/                 # Static files (CSS, JS, images)
```

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Push your branch to your forked repository.
5. Submit a pull request.

---
# images
![image](https://github.com/user-attachments/assets/d8330e22-01a1-436c-b4f3-929e853c4c92)
![image](https://github.com/user-attachments/assets/94df530b-f148-476d-b942-b5da2407dcd4)
![image](https://github.com/user-attachments/assets/7f7aa9a1-f47c-43e2-86b3-2f821ca1e31c)
![image](https://github.com/user-attachments/assets/7e8b816d-caaf-4048-a68e-959568cc920c)
![image](https://github.com/user-attachments/assets/66ed3446-4e15-4c4d-be4a-a81b553c0c06)


## Acknowledgments

- Flask Documentation: https://flask.palletsprojects.com/
- Bootstrap Documentation: https://getbootstrap.com/
- SQLAlchemy Documentation: https://www.sqlalchemy.org/

---

Enjoy using the Hospital Management System! 😊
