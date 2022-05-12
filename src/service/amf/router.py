import re

from twisted.web.resource import Resource, NoResource

from rsc.const import SM_CTX_CB_SVC, N1_N2_MSG_SVC
from src.service.amf import pattern
from src.service.amf.SmCtxStatusCallback import SmCtxStatusCallback
from service.amf.n1n2msg import N1N2Msg


class Router(Resource):
    isLeaf = False

    def __init__(self, to_main_queue, redis_pool):
        super().__init__()
        # 服务单例
        self.to_main_queue = to_main_queue
        self.sub_rsc = {
            N1_N2_MSG_SVC: N1N2Msg(self, redis_pool),
            SM_CTX_CB_SVC: SmCtxStatusCallback(self, redis_pool)
        }

    def getChild(self, path, request):
        """
        路由表
        :param path: 此资源节点的子节点名，也就是两个斜杠中的字符串
        :param request: 从客户端传过来的完整请求
        :return:
        """
        if re.match(pattern.amf_n1n2_msg, str(request.path, encoding="utf-8")):
            return self.sub_rsc["n1_n2_msg"]
        if re.match(pattern.amf_ctx_status_callback, str(request.path, encoding="utf-8")):
            return self.sub_rsc["sm_ctx_cb"]

        return NoResource

    def dispatch_response(self, rsp):
        type = rsp['msg_type']
        if type in self.sub_rsc:
            target_rsc = self.sub_rsc[type]
            target_rsc.set_rsp(rsp)

    def reset_rsp_task(self):
        for rsc in self.sub_rsc.values():
            rsc.reset_rsp_dict()
