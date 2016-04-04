from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from ..models import User


#登录表单
class LoginForm(Form):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),Email()]) #邮箱，三方验证
    password = PasswordField('密码', validators=[DataRequired()])                #密码
    remember_me = BooleanField('记住登录状态')                                   #是否记住登录状态
    submit = SubmitField('登录')                                            #提交

#注册表单
class RegistrationForm(Form):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64), \
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,\
               '用户名仅支持字母、数字、.及下划线，并且必须以字母开头。')])
    #正则表达式保证用户名的格式
    password = PasswordField('密码', validators=[DataRequired(), \
        EqualTo('password2', message='两次密码不匹配。')])
    #与验证密码相同
    password2 = PasswordField('确认密码', validators=[DataRequired()])
    submit = SubmitField('注册')
    #验证该邮箱是否已被注册
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已被注册过。')
    #验证该用户是否已被注册
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('该用户名已存在。')

#修改密码表单
class ChangepwdForm(Form):
    old_password = StringField('旧密码', validators=[DataRequired()])
    new_password = StringField('新密码', validators=[DataRequired(),\
        EqualTo('new_password2', message='输入的两次密码不一致。')])
    new_password2 = StringField('确认新密码', validators=[DataRequired()])
    submit = SubmitField('修改密码')

#通过邮箱重置密码
class ResetpwdForm(Form):
    email = StringField('注册邮箱',validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('新密码', validators=[DataRequired(), \
        EqualTo('password2', message='输入的两次密码不一致。')])
    password2 = PasswordField('确认新密码', validators=[DataRequired()])
    submit = SubmitField('重置密码')
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('该邮箱没有被注册过。')
#通过邮箱重置密码请求
class ResetpwdReqForm(Form):
    email = StringField('注册邮箱',validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('重置密码')

#重置邮箱表单
class ChangeEmailForm(Form):
    email = StringField('新邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    password = StringField('密码', validators=[DataRequired()])
    submit = SubmitField('修改')
    def validate_eamil(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已经被注册过！')