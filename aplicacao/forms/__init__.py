from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, length, email, equal_to


class FormLogin(FlaskForm):
    usuario = StringField('Usuário', validators=[DataRequired(), length(5, 12)])
    senha = PasswordField('Senha', validators=[DataRequired(), length(6, 18)])
    lembrar = BooleanField('Lembrar-se')
    submit_entrar = SubmitField('Entrar')

class FormCadastrarUsuario(FlaskForm):
    usuario = StringField('Nome de Usuário', validators=[DataRequired(), length(5, 12)])
    email = StringField('e-mail', validators=[DataRequired(), email()])
    senha = PasswordField('Senha', validators=[DataRequired(), length(6, 18)])
    confirmacao = PasswordField('Confirmação de Senha', validators=[DataRequired(), equal_to('senha')])
    submit_criar = SubmitField('Cria')