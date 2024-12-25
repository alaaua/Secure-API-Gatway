import jwt
import datetime

# Generate JWT Token
def generate_token(user_data, secret_key):
    payload = {
        "user": user_data,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

# Validate JWT Token
def validate_token(token, secret_key):
    try:
        jwt.decode(token, secret_key, algorithms=["HS256"])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
