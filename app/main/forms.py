
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, BooleanField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Regexp
from wtforms import ValidationError
from ..models import Role, User
from flask.ext.pagedown.fields import PageDownField
#自定义表单
class NameForm(Form):
    name = StringField("What's your name? ", validators=[DataRequired()])  #姓名
    submit = SubmitField("提交")

#用户资料自我编辑表单
class EditProfileForm(Form):
    name = StringField('Real name', validators=[Length(0,64)])
    location = StringField('Location', validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')


class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1,64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1,64),\
                Regexp('^[a-zA-Z][a-zA-Z0-9_.]*$', 0, 'Usernames must have only letters'
                        +', numbers, dots or underscores.')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)   #用户角色可选
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')
    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        #定义下拉菜单的选项
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user   #保存要修改资料的用户模型

    #若修改邮箱，则邮箱不能已经注册
    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Email has Registered!')
    def validate_username(self, field):
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError("Username already in use.")

#文章表单
class PostForm(Form):
    #body = TextAreaField("What's on your mind?", validators=[DataRequired(), Length(min=100)])
    body = PageDownField("What's on your mind?", validators=[DataRequired()])
    submit = SubmitField('Submit')

#评论表单
class CommentForm(Form):
    body = StringField('Enter your comment', validators=[DataRequired()])
    submit = SubmitField('Submit')