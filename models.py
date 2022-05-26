#!/usr/bin/env python3
import pickle
from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha256
from playhouse.apsw_ext import APSWDatabase, BlobField, CharField, DateTimeField, Model

db = APSWDatabase("sqlite.db")


class BaseModel(Model):
    class Meta:
        database = db


class Workspace(BaseModel):
    customerId = CharField(primary_key=True)
    subscription = CharField()
    resourceGroup = CharField()
    name = CharField()
    seen = DateTimeField(default=datetime.now)


class CacheModel(BaseModel):
    funcname = CharField(index=True)
    arghash = CharField(primary_key=True)
    result = BlobField()
    expires = DateTimeField(index=True)


def cache(seconds=300, maxsize=10000):
    "Cache function that can cache anything picklable and cleans expired items when maxsize reached"

    def wrapper(func):
        @wraps(func)
        def call(*args, **kwargs):
            funcname = func.__name__
            arghash = sha256(pickle.dumps((funcname, args, kwargs))).hexdigest()
            cached = CacheModel.get_or_none(
                CacheModel.arghash == arghash, CacheModel.expires > datetime.now()
            )
            if cached is None:
                result = func(*args, **kwargs)
                CacheModel.delete().where(CacheModel.arghash == arghash).execute()
                CacheModel.create(
                    funcname=funcname,
                    arghash=arghash,
                    result=pickle.dumps(result),
                    expires=datetime.now() + timedelta(seconds=seconds),
                )
            else:
                result = pickle.loads(cached.result)
            # cleanup old CacheModel
            if CacheModel.select(CacheModel.funcname == funcname).count() >= maxsize:
                CacheModel.delete().where(CacheModel.expires < datetime.now()).execute()
            return result

        def uncached(*args, **kwargs):
            funcname = func.__name__
            arghash = sha256(pickle.dumps((funcname, args, kwargs))).hexdigest()
            result = func(*args, **kwargs)
            CacheModel.delete().where(CacheModel.arghash == arghash).execute()
            CacheModel.create(
                funcname=funcname,
                arghash=arghash,
                result=pickle.dumps(result),
                expires=datetime.now() + timedelta(seconds=seconds),
            )
            return result

        call.uncached = uncached

        return call

    return wrapper


db.create_tables([Workspace, CacheModel])
