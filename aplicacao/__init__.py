from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = '48d3a419c01e4b01b3976596aefc278d'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///siteprodutos.db'


database = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'realize o login!!'
login_manager.login_message_category = 'alert alert-warning'

from aplicacao import routers