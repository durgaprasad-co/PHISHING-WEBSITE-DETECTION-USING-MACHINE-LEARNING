# PhishDetect: Phishing URL Detection System
## Project Overview
PhishDetect is a web-based application designed to detect and classify URLs as legitimate or phishing. It leverages machine learning models to safeguard users from fraudulent websites. The app provides easy-to-use functionality for URL analysis, user management, and an admin dashboard.
## Features
- URL Prediction: Analyze URLs to identify phishing attempts.
- User Dashboard: Track and visualize prediction stats.
- Admin Panel: Manage users and view prediction logs.
- Dark and Light Mode: Seamlessly toggle between themes for a better user experience.
## Technologies Used
- **Flask**: Python-based web framework.
- **SQLite**: Lightweight relational database.
- **Bootstrap**: Front-end framework for responsive design.
- **Chart.js**: JavaScript library for interactive data visualization.
- **Scikit-learn**: Machine learning library for URL classification.
## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishdetect.git
cd phishdetect
pip install -r requirements.txt
python app.py

#### **6. Usage**
Explain how to use the app:
```plaintext
## Usage
- **Login/Register**: Create an account or log in to access the dashboard.
- **Submit URL**: Paste the URL into the input box on the home page to analyze it.
- **View Results**: See prediction results and track statistics on the dashboard.
- **Admin Panel**: Admin users can manage user accounts and view detailed prediction logs.

## Screenshots
![Dashboard](static/images/dashboard.png)
![Admin Panel](static/images/admin_panel.png)

## API Endpoints
- `/predict`: POST endpoint for URL predictions.
- `/admin`: Protected route for admin functionalities.
- `/dashboard`: User-specific stats and data visualization.

## Contributions
Contributions are welcome! Feel free to submit issues or pull requests.
## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
## Contact
For any inquiries or support, contact:
- Name: [A.Durga prasad]
- Email: durgaprasadalda@gmail.com.com
