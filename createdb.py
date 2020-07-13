#Reference: http://www.rmunn.com/sqlalchemy-tutorial/tutorial.html

from sqlalchemy import *

db = create_engine('sqlite:///spellcheckwebapp.db')

metadata = MetaData(db)

users = Table('users', metadata,
    Column('id', Integer, primary_key=True),
    Column('username', String(40)),
    Column('password', String),
    Column('twofa', String),
)
users.create()

queries = Table('queries', metadata,
    Column('query_id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('query', String),
    Column('response', String),
)
queries.create()
