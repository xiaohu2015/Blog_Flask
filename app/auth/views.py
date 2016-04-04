from flask import render_template, redirect, request, url_for, flash
from flask.ext.login import login_user, login_required, logout_user, current_user
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm, ChangepwdForm, ResetpwdForm, ResetpwdReqForm, ChangeEmailForm
from .. import db
from ..emails import send_email

@auth.before_app_request    #在请求之前对未验证邮箱账户重定向在未验证页面
def before_request():
    if current_user.is_authenticated:
        current_user.ping()   #刷新登陆时间
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

#未验证页面视图
@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:  #对于匿名账户或者已经验证账户重定向到主页面
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


#登录视图
@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):   #验证密码
            login_user(user, form.remember_me.data)    #根据是否记住登录状态注册用户会话
            #如果无请求，返回主页
            return redirect(request.args.get('next') or url_for('main.index'))
        #用户名或密码错误，显示错误信息
        flash('用户名或密码错误.')
    return render_template('auth/login.html', form=form)

#退出视图
@auth.route('/logout')
@login_required   #装饰器，只有登录用户才能访问
def logout():
    logout_user()   #删除并重设用户对话
    flash('您成功退出系统')
    return redirect(url_for('main.index'))

#注册视图
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, \
        password=form.password.data)
        db.session.add(user)
        db.session.commit()  #将用户提交给数据库
        token = user.generate_confirmation_token()  #生成邮箱加密签名
        #发送验证邮件
        send_email(user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token)
        flash('验证邮件已经发到您的邮箱.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)

#邮箱验证链接处理视图
@auth.route('/confirm/<token>')
@login_required       #只有登录用户才可以验证
def confirm(token):
    if current_user.confirmed:      #对于已经验证的用户，忽略，返回主页
        return redirect(url_for('main.index'))
    if current_user.confirm(token):     #对于未验证用户，根据验证结果返回信息
        flash('您成功验证了您的邮箱，谢谢!')
    else:
        flash('链接无效或者过期.')
    return redirect(url_for('main.index'))   #返回主页

#重新发送邮箱验证链接
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('新的验证邮件已经发到您的邮箱.')
    return redirect(url_for('main.index'))

#修改密码视图
@auth.route('/changepwd', methods=['GET', 'POST'])
@login_required
def changepwd():
    form = ChangepwdForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            #验证旧密码是否与新密码一致
            current_user.password = form.new_password.data
            db.session.add(current_user)
            #更新密码
            flash('你已经成功修改密码！')
            return redirect(url_for('main.index')) #重定向到主页
        else:
            flash('旧密码错误')
    return render_template('auth/changepwd.html', form=form)

#密码找回视图
@auth.route('/reset',methods=['GET', 'POST'])
def pwd_reset_request():
    if not current_user.is_anonymous:  #对于已经登录用户，重定向至主页
        return redirect('main.index')
    form = ResetpwdReqForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
            flash('重置密码链接已经发到你的邮箱！')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

#处理密码找回链接视图
@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetpwdForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect('main.index')
        if user.reset_password(token, form.password.data):
            flash('密码重置成功.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)

#修改邮箱视图
@auth.route('/changeEmail', methods=['GET', 'POST'])
@login_required
def changeEmail():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_change_email_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions to confirm your new email '
                  'address has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template('auth/change_email.html', form=form)

#处理修改邮箱链接
@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('Your email address has been updated.')
    else:
        flash('Invalid request.')
    return redirect(url_for('main.index'))
