# -*- coding:utf-8 -*-
'''
author: Ye Hu
装饰器
'''

from functools import wraps
from flask import abort
from flask.ext.login import current_user
from .models import Permission
#对于无权限用户抛出403状态码
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

#管理员群权限装饰器
def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)