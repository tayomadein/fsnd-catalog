from functools import wraps
from flask import redirect

def login_required(login_session):
    ''' Decorator to protect pages that require auth '''
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'username' not in login_session:
                return redirect('/login')
            return func(*args, **kwargs)
        return wrapper
    return decorator


