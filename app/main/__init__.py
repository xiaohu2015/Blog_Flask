from flask import Blueprint
main = Blueprint('main', __name__)
from . import views, errors

from ..models import Permission

#将权限类注入到模板全局中
@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)