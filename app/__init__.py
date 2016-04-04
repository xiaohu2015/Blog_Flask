'''
程序包的构造函数
'''
from flask import Flask  #主程序
from flask.ext.bootstrap import Bootstrap      #模板
from flask.ext.mail  import Mail                 #邮件服务
from flask.ext.moment import Moment              #时间服务
from flask.ext.sqlalchemy import SQLAlchemy      #数据库服务
from flask.ext.pagedown import PageDown        #支持富文本

from config import config                       #导入配置
from flask.ext.login import LoginManager       #认证管理

#认证管理对象
login_manager = LoginManager()
login_manager.session_protection = 'strong'  #认证管理的强度
login_manager.login_view = 'auth.login'     #设置登录页面的端点

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    #注册主程序蓝本
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    #注册蓝本
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    return app

