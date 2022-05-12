import json

import redis
from redis import DataError
from twisted.web.resource import Resource, NoResource

from rsc.const import SM_CTX_CB_SVC
from utils import get_name


def get_imsi_session(request):
    path_str = str(request.path, encoding="utf-8")
    return path_str.split('/')[-2], path_str.split('/')[-1]


class SmCtxStatusCallback(Resource):
    isLeaf = True
    desc = SM_CTX_CB_SVC

    def __init__(self, p_rsc, redis_pool):
        super().__init__()
        self.p_rsc = p_rsc
        if redis_pool:
            self.redis_buffer = redis.Redis(connection_pool=redis_pool)
        else:
            self.redis_buffer = redis.Redis(host='172.17.0.44', password='123456', db=10)

    def render_POST(self, request):
        if request.code == 200:
            imsi, pid = get_imsi_session(request)
            if self.check_exist(imsi, pid):
                print("Exist in dict!")
            request.setResponseCode(204)
            return b""

        return NoResource

    # 键为imsi和session_id的元组
    def set_rsp(self, config):
        name = get_name(config["imsi"], config["session_id"])
        content = json.dumps(config["content"])
        try:
            self.redis_buffer.rpush(name, content)
            return True
        except DataError:
            return False

    def get_rsp(self, imsi, sid):
        name = get_name(imsi, sid)
        return self.redis_buffer.lpop(name)

    def check_exist(self, imsi, sid):
        name = get_name(imsi, sid)
        return self.redis_buffer.exists(name)
