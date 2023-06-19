from aplicacao import app, database, bcrypt
from flask import redirect, render_template, url_for, flash
from aplicacao.forms import FormLogin, FormCadastrarUsuario
from aplicacao.models import Usuario
from flask_login import login_user, logout_user,login_required


@app.route('/', methods=['GET', 'POST'])
def login():
    form = FormLogin()
    if form.validate_on_submit():
        user = Usuario.query.filter_by(usuario=form.usuario.data).first()
        if user and bcrypt.check_password_hash(user.senha, form.senha.data ):
            login_user(user, remember=form.lembrar.data)
            flash(f'login feito {form.usuario.data}', 'alert alert-success')
            return redirect(url_for('produtos'))
        else:
            flash(f'Usuario ou senha errados', 'alert alert-danger')
    return render_template('login.html', form=form)


@app.route('/sair')
@login_required
def sair():
    logout_user()
    flash(f'Sessão encerrada', 'alert alert-info')
    return redirect(url_for('login'))


@app.route('/cadastro-usuario', methods=['GET', 'POST'])
@login_required
def cadastro_usuario():
    form = FormCadastrarUsuario()
    if form.validate_on_submit():
        senha_crypto = bcrypt.generate_password_hash(form.senha.data)
        print(f'senha{form.usuario.data}')
        print(f'senha cripitografada{senha_crypto}')
        user = Usuario(usuario=form.usuario.data, email=form.email.data, senha=form.senha.data)
        database.session.add(user)
        database.session.commit()
        return redirect('produtos')
    return render_template('cadastrar_usuario.html', form=form)


@app.route('/produtos')
@login_required
def produtos():
    produtos = ['Caneca', 'Caneta', 'Caderno', 'TV', 'Notebook']
    return render_template('lista_produto.html', nomes=produtos)
