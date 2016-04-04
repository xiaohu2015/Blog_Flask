import os
from app import create_app, db
from app.models import User, Role, Post, Follow, Comment
from flask.ext.script import Manager, Shell
from flask.ext.migrate import Migrate, MigrateCommand

app = create_app('default')
manager = Manager(app)
migrate = Migrate(app, db)

def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role, Post=Post, Follow=Follow, Comment=Comment)

manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)
#数据库迁移指令
'''
脚本命令  cd E:\Python_project\Flasky
python manage.py runserver --host 0.0.0.0

创建数据库迁移仓库： python manage.py db init
迁移脚本 python manage.py db migrate -m "initial migration"
更新数据库： python manage.py db upgrade
#运行脚本环境 python manage.py shell
Comment.generate_comments()
http://gravatar.com/avatar/
http://gravatar.com/avatar/4bc7e8834a6fd8f9334ef878ad58ecf5

'''

if __name__ == '__main__':
    #app.run(host = '0.0.0.0')
    manager.run()

