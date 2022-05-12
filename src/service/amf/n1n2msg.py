import json

import redis
from redis import DataError
from twisted.web.resource import Resource, NoResource

from src.components.rsp_decoder import preprocess_multi_rsp
from rsc.const import N1_N2_MSG_SVC

N1N2_MSG_JSON = "./data_stream/printable_txt/n1_n2_msg"


def get_imsi_num(request):
    path_str = str(request.path, encoding="utf-8")
    return path_str.split('/')[-2]


class N1N2Msg(Resource):
    isLeaf = True
    desc = N1_N2_MSG_SVC

    def __init__(self, p_rsc, redis_pool):
        super().__init__()
        self.p_rsc = p_rsc
        if redis_pool:
            self.redis_buffer = redis.Redis(connection_pool=redis_pool)
        else:
            self.redis_buffer = redis.Redis(host='172.17.0.44', password='123456', db=11)

    def render_POST(self, request):
        # content = request.content.read().hex()
        # print(content)
        # print(unhexlify(content))
        # raw_content = unhexlify(content)
        # content_arr = raw_content.split(b'------Boundary\r\n')
        # info = json.loads(unhexlify(content).decode())
        mp_obj = preprocess_multi_rsp(request)
        json_info = mp_obj.data_content
        print(json.dumps(json_info, indent=4))

        if request.code == 200:
            # 仅支持json
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            imsi_num = get_imsi_num(request).split("-")[1]
            pdu_id = json_info['pduSessionId']
            self.p_rsc.to_main_queue.put((self.desc, imsi_num, pdu_id))
            if self.check_imsi(imsi_num):
                return self.redis_buffer.lpop(imsi_num)
            return json.dumps({"cause": "N1_N2_TRANSFER_INITIATED"}).encode('utf-8')

        return NoResource

    def check_imsi(self, imsi):
        return self.redis_buffer.exists(imsi)

    # 键为imsi
    def set_rsp(self, config):
        imsi_num = config["imsi"]
        content = json.dumps(config["content"])
        try:
            self.redis_buffer.rpush(imsi_num, content)
            return True
        except DataError:
            return False
