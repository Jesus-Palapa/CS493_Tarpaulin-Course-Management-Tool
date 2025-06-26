
# CS493_Tarpaulin-Course-REST API
Implemented a RESTful API for an application called Tarpaulin, a lightweight course management tool that's an "alternative" to Canvas. The API application was deployed on Google Cloud Platform using Google App Engine and Datastore, using Python 3, and used Auth0 for authentication. It was part of the CS394 course at Oregon State University.

## 🚀 Features
- Full REST API with 13 endpoints
- Role-based access control (Admin, Instructor, Student)
- JWT authentication with Auth0
- CRUD operations for courses and enrollments
- Deployed on Google App Engine
- Uses Google Cloud Datastore for persistent storage

## 🔐 Authentication
Most endpoints are protected and require authentication via Auth0. Users must provide a valid JWT token in the `Authorization` header as a Bearer token.
Roles:
- **Admin**: Manage all resources
- **Instructor**: Manage their own courses
- **Student**: View enrolled courses

## 🏗️ Tech Stack
- **Backend:** Python 3, Flask
- **Database:** Google Cloud Datastore
- **Hosting:** Google App Engine
- **Authentication:** Auth0 (JWT-based)

## ⚙️ Setup Instructions

### 
1️⃣ Clone the Repository
  git clone https://github.com/YourUsername/tarpaulin-api.git
  cd tarpaulin-api
2️⃣ Create a Virtual Environment (Optional but recommended)
  python3 -m venv venv
  source venv/bin/activate
3️⃣ Install Dependencies
  pip install -r requirements.txt
4️⃣ Configure Environment Variables
  Create a .env file in the root directory with the following variables:
  AUTH0_CLIENT_ID=your_client_id
  AUTH0_CLIENT_SECRET=your_client_secret
  AUTH0_DOMAIN=your_domain.auth0.com
  API_AUDIENCE=your_api_identifier
  ALGORITHMS=RS256
  GOOGLE_CLOUD_PROJECT=your_project_id
5️⃣ Run the App Locally
  python main.py
6️⃣ Deploy to Google App Engine
  gcloud app deploy


🔥 Example Endpoints
	Functionality    Endpoint	    Protection	    Description
1. User login    POST /users/login    Pre-created Auth0 users with username and password    Use Auth0 to issue JWTs. Feel free to use the code of the example app presented in Exploration - Implementing Auth Using JWTs. Using that code example requires only minor changes in the response.

2. Get all users    GET /users    Admin only    Summary information of all 9 users. No info about avatar or courses.

3. Get a user    GET /users/:id    Admin. Or user with JWT matching id    Detailed info about the user, including avatar (if any) and courses (for instructors and students)

4. Create/update a user’s avatar    POST /users/:id/avatar    User with JWT matching id    Upload file to Google Cloud Storage.

5. Get a user’s avatar    GET /users/:id/avatar    User with JWT matching id    Read and return file from Google Cloud Storage.

6. Delete a user’s avatar    DELETE /users/:id/avatar    User with JWT matching id    Delete file from Google Cloud Storage.

7. Create a course    POST /courses    Admin only    Create a course.

8. Get all courses    GET /courses    Unprotected    Paginated using offset/limit. Page size is 3. Ordered by "subject."  Doesn’t return info on course enrollment.

9. Get a course    GET /courses/:id    Unprotected    Doesn’t return info on course enrollment.

10. Update a course    PATCH /courses/:id    Admin only    Partial update.

11. Delete a course    DELETE /courses/:id    Admin only    Delete course and delete enrollment info about the course.

12.	Update enrollment in a course    PATCH /courses/:id/students    Admin. Or instructor of the course.    Enroll or disenroll students from the course.

13.	Get enrollment for a course    GET /courses/:id/students    Admin. Or instructor of the course.    All students enrolled in the course.


🚧 Known Limitations / Future Improvements
Currently limited to basic role-based access control.

Future improvements could include:
UI frontend
Enhanced error handling
Pagination for large datasets

🤝 Acknowledgements
Oregon State University - CS 493 Cloud Application Development
Auth0 for authentication
Google Cloud for hosting and storage

✍️ Author
Jesus Palapa

📜 License
This project is for educational purposes only.

Implemented a RESTful API for an application called Tarpaulin, a lightweight course management tool that's an "alternative" to Canvas. The API application was deployed on Google Cloud Platform using Google App Engine and Datastore, using Python 3, and used Auth0 for authentication.
