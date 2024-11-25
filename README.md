I've implemented a complete authentication service that meets all 
the requirements. Here's how to test each endpoint using curl commands:

> Using Python(3.8)
## Key Features:

1. User authentication with email and password
2. JWT-based token system with separate access and refresh tokens
3. Token blacklisting for logout functionality
5. Created a file-based storage system using JSON files
5. Proper error handling with appropriate HTTP status codes
6. Password hashing using bcrypt
7. Token expiration (30 minutes for access tokens, 7 days for refresh tokens)

### To set up and run the project:

1. Create a virtual environment and activate it ```python -m venv venv```
2. Install dependencies: ```pip install -r requirements.txt```
3. Run the application: ```python app.py```


### CURL Commands for testing Endpoints.

* **Sign Up** 


`curl -X POST http://localhost:5000/signup \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "password123"}'`

* **Sign In**


`curl -X POST http://localhost:5000/signin \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "password123"}'
`

> **NOTE** : Paste your access token before trying the following commands.



* **Access Protected Endpoint**

`
curl -X GET http://localhost:5000/protected \
-H "Authorization: Bearer <access_token>"`

* **Logout (Revoke Token)**

`curl -X POST http://localhost:5000/logout \
-H "Authorization: Bearer <access_token>"`


* **Refresh Token**

`curl -X POST http://localhost:5000/refresh \
-H "Authorization: Bearer <refresh_token>"`