from flask import Flask, request, jsonify, send_file
from google.cloud import storage, datastore

import io
import requests
import json

from google.cloud.datastore.query import PropertyFilter
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users"
COURSES = "courses"
PHOTO_BUCKET = "a6-avatar-palapacj"

# Update the values of the following 3 variables
CLIENT_ID = 'your-client-id'
CLIENT_SECRET = 'your-secret'
DOMAIN = 'your-domain.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return None
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return None
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users to use this API"\

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/'+ USERS +'/login', methods=['POST'])
def login_user():
    token = {}
    try:
        content = request.get_json()
        username = content["username"]
        password = content["password"]
    except:
        raise AuthError({"Error":"The request body is invalid"}, 400)
    try:
        body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
            }
        headers = { 'content-type': 'application/json' }
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        response_data = r.json()
        token["token"] = response_data["id_token"]
        return token, 200, {'Content-Type':'application/json'}
    except:
        raise AuthError({"Error":"Unauthorized"}, 401)

# Get all users if the Authorization header contains a valid JWT    
@app.route("/" + USERS, methods=['GET'])
def get_users():
    verified_user = False
    payload = verify_jwt(request)
    query = client.query(kind=USERS)
    results = list(query.fetch())
    # Check if Auth header was valid
    if payload is None:
        return ({"Error":"Unauthorized"}, 401)
    else:  
        # Get request sub value to match with existing user,
        # Returns list if admin role verified 
        sub_value = payload["sub"]
        for r in results:
            r['id'] = r.key.id
            if 'avatar' in r:
                del r['avatar']
            if r["sub"] == sub_value:
                if r["role"] == "admin":
                    verified_user = True
            continue
        if verified_user:
            return(results, 200) 
        return ({"Error":"You don't have permission on this resource"}, 403)
    
# Get a user if the Authorization header contains a valid JWT
@app.route("/" + USERS + "/<int:id>", methods=['GET'])
def get_user(id):
    courses = []
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401) 
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    if user is None:
        return ({"Error": "You don't have permission on this resource"}, 403)
    sub_value = payload["sub"]
    if user["role"] != "admin" and user["sub"] != sub_value:
        return ({"Error": "You don't have permission on this resource"}, 403)
    user["id"] = user.key.id 
    if user["role"] == "admin":
        if "avatar" in user:
            storage_client= storage.Client()
            bucket = storage_client.bucket(PHOTO_BUCKET)
            blob = bucket.blob(user["avatar"])
            user["avatar_url"] = blob.public_url
            user.pop("avatar")
        return user
    elif user["role"] == "instructor":
        instructor_query = client.query(kind=COURSES)
        instructor_query.add_filter(filter=PropertyFilter('instructor_id', '=', id))
        results = list(instructor_query.fetch())
        for r in results:
            courses.append(request.scheme + "://" + request.host + "/" + COURSES + "/" + str(r.key.id))
        user["courses"] = courses
        if "avatar" in user:
            storage_client= storage.Client()
            bucket = storage_client.bucket(PHOTO_BUCKET)
            blob = bucket.blob(user["avatar"])
            user["avatar_url"] = blob.public_url
            user.pop("avatar")
        return user

    elif user["role"] == "student":
        student_query = client.query(kind=COURSES)
        student_query.add_filter(filter=PropertyFilter("enrolled", "=", id))
        results = list(student_query.fetch())
        for r in results:
            courses.append(request.scheme + "://" + request.host + "/" + COURSES + "/" + str(r.key.id))
        user["courses"] = courses
        if "avatar" in user:
            storage_client= storage.Client()
            bucket = storage_client.bucket(PHOTO_BUCKET)
            blob = bucket.blob(user["avatar"])
            user["avatar_url"] = blob.public_url
            user.pop("avatar")
        return user


# Create/Update user avatar if the Authorization header contains a valid JWT
@app.route('/'+ USERS + '/<int:id>' + '/avatar' , methods=['POST'])
def user_avatar(id):
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401)
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    sub_value = payload["sub"]
    if user["sub"] != sub_value:
        return ({"Error": "You don't have permission on this resource"}, 403)   
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return ({"Error": "The request body is invalid"}, 400)
    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)
    user.update({
        'avatar': file_obj.filename
    })
    client.put(user)       
    return ({"avatar_url": blob.public_url},200)

# Get a users avatar if the Authorization header contains a valid JWT
@app.route('/'+ USERS + '/<int:id>' + '/avatar' , methods=['GET'])
def get_image(id):
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401)
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    sub_value = payload["sub"]
    if user["sub"] != sub_value:
        return ({"Error": "You don't have permission on this resource"}, 403)
    if "avatar" not in user:
        return ({"Error": "Not found"}, 404) 
    
    file_name = user["avatar"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(file_name)
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

# Delete an avatar if the Authorization header contains a valid JWT 
@app.route('/'+ USERS + '/<int:id>' + '/avatar', methods=['DELETE'])
def delete_image(id):
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401)
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    sub_value = payload["sub"]
    if user["sub"] != sub_value:
        return ({"Error": "You don't have permission on this resource"}, 403)
    if "avatar" not in user:
        return ({"Error": "Not found"}, 404) 
    
    file_name = user["avatar"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    # Delete the file from Cloud Storage
    blob.delete()

    user.pop("avatar")
    client.put(user)
    return '',204

# Create a course if an admin role and if the Authorization header contains a valid JWT
@app.route('/' + COURSES, methods=['POST'])
def post_courses():
    verified_instructor = False
    verified_admin = False
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401)
    query = client.query(kind=USERS)
    results = list(query.fetch())
    sub_value = payload["sub"]
    for r in results:
        if r["sub"] == sub_value:
            if r["role"] == "admin":
                verified_admin = True
        continue
    if verified_admin:
        count = 0
        content = request.get_json()
        for c in content:
            count +=1
        if count != 5:
            return ({"Error": "The request body is invalid"}, 400)
        for r in results:
            r["id"] = r.key.id
            if r["id"] == content["instructor_id"]:
                if r["role"] == "instructor":
                    verified_instructor = True
            continue
        if verified_instructor:
            new_key = client.key(COURSES)
            new_course = datastore.Entity(key=new_key)
            new_course.update({
                'subject': content['subject'],
                'number': content['number'], 
                'title': content['title'],
                'term': content['term'],
                'instructor_id': content['instructor_id']
            })
            client.put(new_course)
            new_course['id'] = new_course.key.id
            new_course['self'] = request.url + "/" + str(new_course['id'])
            return (new_course, 201)
        else:
            return ({"Error": "The request body is invalid"}, 400) 
    else:
        return ({"Error":"You don't have permission on this resource"}, 403) 

# Get all courses
@app.route("/" + COURSES, methods=['GET'])
def get_courses():
    content= {}
    courses_list = []
    query = client.query(kind=COURSES)
    query.order = ["subject"]
    if request.args.get('limit') is None:
        limit_query = 3
        offset_query = 0
    else:
        limit_query = int(request.args.get('limit'))
        offset_query = int(request.args.get('limit'))

    c_iterator = query.fetch(limit=limit_query, offset=offset_query)
    pages = c_iterator.pages
    results = list(next(pages))

    for r in results:
        r['id'] = r.key.id
        r['self'] = request.base_url + "/" + str(r['id'])
        if "enrolled" in r:
            r.pop("enrolled")
        courses_list.append(r)
    content["courses"] = courses_list
    content["next"] = request.base_url + "?offset=" + str(3+offset_query) + "&limit=" + str(limit_query)
    return (content, 200)

# Get a course
@app.route('/' +  COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return ({"Error": "Not found"}, 404)
    else:
        course["id"] = course.key.id
        course['self'] = request.url
        if "enrolled" in course:
            course.pop("enrolled")
        return course
    
# Update a course
@app.route("/" + COURSES + "/<int:id>", methods=['PATCH'])
def put_course(id):
    verified_admin = False
    verified_instructor = False
    content = request.get_json()
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401)
    else:
        query = client.query(kind=USERS)
        user_results = list(query.fetch())
        sub_value = payload["sub"]
        for u in user_results:
            if u["sub"] == sub_value:
                if u["role"] == "admin":
                    verified_admin = True
                break
        if verified_admin:

            if "instructor_id" not in content:
                course_key = client.key(COURSES, id)
                course = client.get(key=course_key)
                course['id'] = course.key.id
                course['self'] = request.url + "/" + str(course['id'])
                return (course, 200)

            for u in user_results:
                u["id"] = u.key.id
                if u["id"] == content["instructor_id"]:
                    if u["role"] == "instructor":
                        verified_instructor = True
                    break
            if verified_instructor:
                course_key = client.key(COURSES, id)
                course = client.get(key=course_key)
                if course is None:
                   return ({"Error":"You don't have permission on this resource"}, 403) 
                course.update(content)
                client.put(course)
                course['id'] = course.key.id
                course['self'] = request.url + "/" + str(course['id'])
                return (course, 200)
            else:
                return ({"Error": "The request body is invalid"}, 400) 
        else:
            return ({"Error":"You don't have permission on this resource"}, 403)

# Delete a course
@app.route("/" + COURSES + "/<int:id>", methods=['DELETE'])
def delete_course(id):
    verified_user = False
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    payload = verify_jwt(request)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401) 
    if course is None:
        return ({"Error": "You don't have permission on this resource"}, 403)
    sub_value = payload["sub"]
    user_query = client.query(kind=USERS)
    user_results = list(user_query.fetch())
    for r in user_results:
        if r["sub"] == sub_value:
            if r["role"] == "admin":
                verified_user = True
        continue
    if verified_user:
        client.delete(course)
        return ('', 204)
    else:
        return ({"Error": "You don't have permission on this resource"}, 403)

# Update enrollment in a course
@app.route("/" + COURSES + "/<int:id>" + "/students", methods=['PATCH'])
def patch_enrollment(id):
    verified_admin = False
    verified_instructor = False
    payload = verify_jwt(request)
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401) 
    if course is None:
        return ({"Error": "You don't have permission on this resource"}, 403)
    query = client.query(kind=USERS)
    user_results = list(query.fetch())
    sub_value = payload["sub"]
    for u in user_results:
        if u["sub"] == sub_value:
            if u["role"] == "admin":
                verified_admin = True
            if u.key.id == course["instructor_id"]:
                verified_instructor = True
            break
    if verified_admin or verified_instructor:
        content = request.get_json()
        add_list = content["add"]
        remove_list = content["remove"]
        common_vals = list(set(add_list).intersection(set(remove_list)))
        if common_vals:
                return ({"Error": "Enrollment data is invalid"}, 409)
        for a in add_list:
            check_user_key = client.key(USERS, a)
            check_user = client.get(key=check_user_key)
            if check_user is None:
                return ({"Error": "Enrollment data is invalid"}, 409)
            if check_user["role"] != "student":
                return ({"Error": "Enrollment data is invalid"}, 409)
        for r in remove_list:
            check_user_key = client.key(USERS, r)
            check_user = client.get(key=check_user_key)
            if check_user is None:
                return ({"Error": "Enrollment data is invalid"}, 409)
            if check_user["role"] != "student":
                return ({"Error": "Enrollment data is invalid"}, 409)
        course_list = []
        if "enrolled" in course:
            course_list = course["enrolled"]
        for a in add_list:
            if a not in course_list:
                course_list.append(a)
        for r in remove_list:
            if r in course_list:
                course_list.remove(r)
        course.update({'enrolled': course_list})
        client.put(course)
        return ('', 200)
    else:
        return ({"Error":"You don't have permission on this resource"}, 403)

# Get enrollment for a course
@app.route("/" + COURSES + "/<int:id>" + "/students", methods=["GET"])
def get_enrollment(id):
    verified_admin = False
    verified_instructor = False
    payload = verify_jwt(request)
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if payload is None:
        return ({"Error":"Unauthorized"}, 401) 
    if course is None:
        return ({"Error": "You don't have permission on this resource"}, 403)
    query = client.query(kind=USERS)
    user_results = list(query.fetch())
    sub_value = payload["sub"]
    for u in user_results:
        if u["sub"] == sub_value:
            if u["role"] == "admin":
                verified_admin = True
            if u.key.id == course["instructor_id"]:
                verified_instructor = True
            break
    if verified_admin or verified_instructor:
        enrolled = []
        if "enrolled" in course:
            enrolled = course["enrolled"]
        return (enrolled, 200)
    else:
        return ({"Error":"You don't have permission on this resource"}, 403)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

