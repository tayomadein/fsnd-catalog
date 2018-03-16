"""
Setup Database for Catalog
"""

#!/usr/bin/env python3

import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
Base = declarative_base()

class User(Base):
    '''User Table'''
    __tablename__ = 'user'

    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    user_id = Column(Integer, primary_key=True) 

class Category(Base):
    ''' Catalog Category Table '''
    __tablename__ = 'category'

    name = Column(String(80), nullable=False)
    cat_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.user_id'))
    user = relationship(User)

    @property
    def serialize(self):
        ''' Serialize function to send JSON objects in a serializable format'''
        return {
            'name': self.name,
            'cat_id': self.id,
        }


class Item(Base):
    ''' Catalog Items Table '''
    __tablename__ = 'item'

    name = Column(String(80), nullable=False)
    item_id = Column(Integer, primary_key=True)
    date_created = Column(DateTime, default = datetime.datetime.utcnow)
    cat_id = Column(Integer, ForeignKey('category.cat_id'))
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.user_id'))
    user = relationship(User)
    category = relationship(Category)

    ## Add a serialize function to send JSON objects in a serializable format
    @property
    def serialize(self):
        ''' Serialize function to send JSON objects in a serializable format'''
        return {
            'name': self.name,
            'description': self.description,
            'item_id': self.item_id,
            'category': self.cat_id,
        }

# ######insert at end of file #######

engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
