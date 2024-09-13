# from flask_jwt_extended import decode_token
# from flask import session
# from yourapp.models import User

# def get_user_from_token():
#     token = session.get('jwt_token')
#     if token:
#         try:
#             decoded_token = decode_token(token)
#             user_id = decoded_token['sub']
#             return User.query.get(user_id)
#         except:
#             return None
#     return None
