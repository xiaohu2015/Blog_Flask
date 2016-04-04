from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from datetime import datetime
import hashlib
from markdown import markdown
import bleach
#两个模型

#加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#权限常量类
class Permission(object):
    FOLLOW = 0x01              #关注其他用户
    COMMENT = 0x02             #评论文章
    WRITE_ARTICLES = 0x04      #写文章
    MODERATE_COMMENTS = 0x08   #管理评论
    ADMINISTER = 0x80          #管理网站

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    #只有一个角色的default字段设为True，其他设为False
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)   #角色权限
    # 加入了lazy = 'dynamic' 参数，从而禁止自动执行查询
    users = db.relationship('User', backref='role', lazy='dynamic')

    #静态方法，添加角色
    @staticmethod
    def insert_roles():
        #角色字典
        roles = {
            'Users': (Permission.FOLLOW | Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW | Permission.COMMENT |
                          Permission.WRITE_ARTICLES | Permission.MODERARE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for role_name in roles:  #对于未创建的角色进行创建
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                role = Role(name=role_name)
                role.permissions = roles[role_name][0]
                role.default = roles[role_name][1]
                db.session.add(role)
            db.session.commit()

    def __repr__(self):
        return '<Roles %r %r  %r>' % (self.id, self.name, self.permissions)

    # 关注关联表模型
class Follow(db.Model):
    __tablename__ = 'follows'
    # 关注者
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    # 被关注者
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # 随机产生关注关系
    @staticmethod
    def followship_generate(count=1000):
        from random import seed, randint
        from sqlalchemy.exc import IntegrityError
        seed()
        user_count = User.query.count()
        while count > 0:
            follower = User.query.offset(randint(0, user_count-1)).first()
            followed = User.query.offset(randint(0, user_count-1)).first()
            if followed != follower:
                try:
                    f = Follow(follower=follower, followed=followed)
                    db.session.add(f)
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
            count = count - 1



#用户
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))   #存储用户的密码散列值
    confirmed = db.Column(db.Boolean, default=False)     #是都验证邮箱信息
    #用户资料
    name = db.Column(db.String(64))  #用户真实姓名
    location = db.Column(db.String(64))  #用户居住地
    about_me = db.Column(db.Text())      #用户自我介绍
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)  #注册时间
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow())   #上次访问时间
    avatar_hash = db.Column(db.String(32))   #保存用户email对应的md5散列值
    #对应的博客文章
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    #返回自己的关注者  用户关联表
    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id], backref=\
                               db.backref('follower', lazy='joined'), lazy='dynamic',
                               cascade='all, delete-orphan')
    #返回关注自己的用户关联表
    followers = db.relationship('Follow', foreign_keys=[Follow.followed_id], backref=\
                                db.backref('followed', lazy='joined'), lazy='dynamic',
                                cascade='all, delete-orphan')
    #用户的评论
    comments = db.relationship("Comment", backref='author', lazy='dynamic')

    @property              #保证无法获取密码
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter         #设置密码
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    def verify_password(self, password):    #验证密码
        return check_password_hash(self.password_hash, password)

    #验证邮箱使用
    def generate_confirmation_token(self, expiration=3600):
        '''
        用于生成特定的验证口令，与用户id绑定
        '''
        s = Serializer(current_app.config['SECRET_KEY'], expiration)   #生成签名
        return s.dumps({'confirm': self.id})     #基于用户id生成加密签名
    def confirm(self, token):
        '''
        用于验证口令是否与用户ID一致
        '''
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True


    #用于密码重置口令的产生
    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})
    #用于重置密码
    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    #用于修改邮箱生成密令
    def generate_change_email_token(self, new_eamil, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email':new_eamil})

    #用于验证修改邮箱链接
    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_eamil = data.get('new_email')
        if new_eamil is None:
            return False
        if self.query.filter_by(email=new_eamil).first() is not None:
            return False
        self.email = new_eamil
        self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True

    def __init__(self, **kwargs):
        #调用父类的初始化函数
        super(User, self).__init__(**kwargs)
        #如果调用父类的构造函数后角色还未定义，则根据注册邮箱判断其为管理员或默认角色
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        #对于有邮箱的生成md5散列值
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        self.follow(self)  #关注自己

    #查看用户是否具有某项权限
    def can(self, permissions):
        return self.role is not None and (self.role.permissions & permissions) == permissions
    #是否是管理员，单独方法
    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    #用户每次登陆，刷新时间
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        #db.session.commit()

    #根据用户邮箱生成头像链接
    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'http://secure.gravatar.com/avatar'
        else:
            url = 'http://gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    #生成虚拟用户
    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py
        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def is_following(self, user):
        '''
        判断自己是否关注某用户
        '''
        return self.followed.filter_by(followed_id=user.id).first() is not None
    def is_followed_by(self, user):
        '''
        判断某用户是否关注自己
        '''
        return self.followers.filter_by(follower_id=user.id).first() is not None
    def follow(self, user):
        '''
        关注某用户
        '''
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)
    def unfollow(self, user):
        '''
        取消对某用户的关注
        '''
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    #返回自己关注的人的文章，设置为属性类型
    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id==Post.author_id).filter(Follow.follower_id==self.id)

    #对以前用户关注自己
    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.is_following(user)
                db.session.add(user)
                db.session.commit()

    def __repr__(self):
        return '<Users %r[%r] %r >' % (self.username, self.role_id, self.last_seen)

class AnonymousUser(AnonymousUserMixin):
    '''
    匿名用户类，未登录用户
    '''
    def can(self, permissions):
            return False
    def is_administrator(self):
            return False
    #管理匿名用户
login_manager.anonymous_user = AnonymousUser

#博客文章数据库模型
class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)                    #正文
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow) #时间
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))            #作者
    body_html = db.Column(db.Text)          #保存文章的html格式代码

    #文章的评论
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    #生成虚拟文章
    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0,user_count-1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1,5)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    #模型中处理Markdown文本
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

#将on_changed_body函数注册在body字段上，当body改变后，函数自动调用
db.event.listen(Post.body, 'set', Post.on_changed_body)

#评论模型
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean, default=False)  #查禁评论
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    @staticmethod
    def generate_comments(count=5000):
        from random import seed, randint
        import forgery_py
        seed()
        user_count = User.query.count()
        post_count = Post.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post.query.offset(randint(0, post_count - 1)).first()
            c = Comment(body=forgery_py.lorem_ipsum.sentences(randint(1, 2)),
                         timestamp = forgery_py.date.date(True), author=u, post=p)
            db.session.add(c)
        pass

db.event.listen(Comment.body, 'set', Comment.on_changed_body)

