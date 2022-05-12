import logging
import threading

import redis
from twisted.internet import endpoints, reactor
from twisted.web import server

from src.entity.base_ne import BaseHttp2NetElement
from src.service.amf.router import Router
from utils import get_h2_server_addr_desc

AMF_PORT = 84


class SimAmf(BaseHttp2NetElement):
    __server = None
    rcv_queue = None
    send_queue = None
    router = None
    cmd_t = None
    redis_pool = redis.ConnectionPool(max_connections=128, host='172.17.0.44', password='123456', db=1)

    def __init__(self):
        self.__logger = logging.getLogger("AMF")

    def start_server(self):
        self.set_server()
        self.set_root_service()
        self.start_cmd_listen()
        reactor.run()

    def set_rcv_queue(self, r_queue):
        self.rcv_queue = r_queue

    def set_send_queue(self, s_queue):
        self.send_queue = s_queue

    def set_server(self, port=None):
        port_num = port if port and port is int else AMF_PORT
        self.__server = endpoints.serverFromString(reactor, get_h2_server_addr_desc(port_num))

    # 设置根资源的时候，子资源会一起初始化
    def set_root_service(self):
        root_rsc = Router(self.send_queue, self.redis_pool)
        self.__server.listen(server.Site(root_rsc))
        self.router = root_rsc

    def start_cmd_listen(self):
        self.cmd_t = threading.Thread(target=self.listen_cmd_from_main, daemon=True)
        self.cmd_t.start()

    def listen_cmd_from_main(self):
        self.__logger.debug("启动命令监听线程")
        while True:
            if self.rcv_queue.empty() is False:
                self.dispatch_function(self.rcv_queue.get())

    def stop_server(self):
        # self.cmd_t.join(timeout=3)
        reactor.stop()

    def dispatch_function(self, cmd_tuple):
        cmd = cmd_tuple[0]
        if cmd == "set_rsp":
            self.router.dispatch_response(cmd_tuple[1])
        if cmd == "reset_task":
            self.router.reset_rsp_task()
        if cmd == "stop_server":
            self.stop_server()
