# ScanSwift Document System

ScanSwift is a powerful document management system that helps users organize, analyze, and search through their documents efficiently. It features AI-powered document similarity matching, topic extraction, and multi-user support.

## Features

- **Document Management**
  - Upload and store documents
  - Extract topics automatically
  - Find similar documents using AI
  - Export scan history as CSV

- **Multi-User Support**
  - User authentication and authorization
  - Admin dashboard for user management
  - Active user tracking
  - Session management

- **Credit System**
  - Daily credit allocation
  - Credit request system
  - Admin approval for credit requests

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/scanswift.git
   cd scanswift
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables**
   Create a `.env` file in the root directory:
   ```
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your_secret_key_here
   DEEPSEEK_API_KEY=your_api_key_here
   ```

5. **Initialize Database**
   ```bash
   python init_db.py
   ```

6. **Run the Application**
   ```bash
   flask run
   ```

7. **Access the Application**
   - Open http://localhost:5000 in your browser
   - Default admin credentials:
     - Username: admin
     - Password: admin123

## Project Structure

```
scanswift/
├── app.py              # Main application file
├── init_db.py          # Database initialization
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── instance/          # Database files
├── static/            # Static files (CSS, JS)
│   ├── css/
│   └── js/
├── templates/         # HTML templates
│   ├── admin/
│   └── auth/
└── test_data/        # Sample documents
```

## Test Data

Sample documents are provided in the `test_data` directory for testing:

1. `sample_report.txt` - A business report
2. `technical_doc.txt` - Technical documentation
3. `meeting_notes.txt` - Meeting minutes

These documents can be used to test:
- Document upload
- Topic extraction
- Similarity matching
- Export functionality

## API Documentation

### Document Management

- `POST /scan_document` - Upload and analyze a document
- `GET /export/scan-history` - Export scan history as CSV
- `GET /documents/<id>` - View document details

### User Management

- `POST /login` - User authentication
- `POST /register` - User registration
- `GET /admin/active-users` - View active users

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
