from aplicacao import app, database, bcrypt
from aplicacao.models import Usuario

with app.app_context():
    database.create_all()

#with app.app_context():
#    database.drop_all()
#    database.create_all()

#with app.app_context():
#    user = Usuario(usuario='admistrador', email='admistrador@gmail.com', senha='123456')
#    database.session.add(user)
#   database.session.commit()

with app.app_context():
    senha_crypto = bcrypt.generate_password_hash('123456')
    user = Usuario(usuario='admin', email='admistrador@gmail.com', senha=senha_crypto)
    database.session.add(user)
    database.session.commit()


#with app.app_context():
#    user = Usuario(usuario='teste01', email='teste01@gmail.com', senha='123456')
#    database.session.add(user)
#    database.session.commit()

with app.app_context():
   usuarios = Usuario.query.all()
   for item in usuarios:
       print(f'{item.usuario}, {item.email}, {item.senha}, {item.id}')

#with app.app_context():
#    user = Usuario.query.filter_by(id=2).first()
#    print(user.usuario)
#    database.session.delete(user)
#    database.session.commit()

