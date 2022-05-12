import datetime
import json
import logging
import multiprocessing as mp
import os
import socket
import time
from queue import Queue, Empty

import redis
from scapy.supersocket import SimpleSocket

from components.ue_lock_manager import UeLockManager
from entity.test_case import TestCase
from rsc.app_config import D4_PFCP_PORT, UPF_GW, D4_CONFIG_PATH, LOGGER_FORMAT, LOGGER_FILENAME, LOGGER_LEVEL
from rsc.const import POST, PDU_SESSION_MODIFY, N1_N2_MSG_SVC, PDU_RELEASE_REQ, PDU_RELEASE_RSP, PDU_RELEASE_COMPLETE, \
    UPF_SESSION_REPORT_REQ
from service.amf.sim_amf import SimAmf
from service.upf.pfcp_upf import PfcpSkeleton
from utils import get_ip

upf_redis_pool = redis.ConnectionPool(max_connections=128, host='172.17.0.44', password='123456', db=2)


class Application:

    def __init__(self):
        # 日志配置
        logging.basicConfig(filename=LOGGER_FILENAME, level=LOGGER_LEVEL, format=LOGGER_FORMAT)
        self.logger = logging.getLogger('main')
        self.UPF_FLAG = 1

        self.tc_list = []  # 测试用例列表
        self.thread_list = []  # 线程级服务器列表，一般指Upf
        self.process_list = []  # 进程级服务器列表，一般指需要http2服务端的
        self.main_to_amf_list = []  # 主程到子程的管道列表
        self.amf_to_main_list = []  # 子程到主程的管道列表

    def load_tc_config(self, config_path):
        """
        加载测试用例，要求测试用例文件夹下用例文件名称为纯数字
        :param config_path:
        """
        for i in range(get_file_num(config_path)):
            self.logger.debug("Load config %s to test case", str(i))
            try:
                raw_file = open(config_path + str(i))
                config = json.load(raw_file)
            except FileNotFoundError:
                self.logger.warning('找不到配置文件 %s%s ', config_path, str(i))
                continue
            test_case = TestCase(config)
            self.tc_list.append(test_case)

    def process_tc(self):
        for tc in self.tc_list:
            tc.process_config()

    def run(self):
        self.load_tc_config(D4_CONFIG_PATH)
        self.process_tc()

        # 服务端配置
        if self.UPF_FLAG:
            config_upf(self.tc_list[0].smf_ip, self.thread_list)  # upf配置
        build_amf(self.process_list, self.main_to_amf_list, self.amf_to_main_list)  # amf配置

        # 服务器启动
        self.process_list[0].start()
        if self.UPF_FLAG:
            for t in self.thread_list:
                t.start()

        # TODO AMF就绪回调
        time.sleep(9)

        # 运行测试用例
        for tc in self.tc_list:

            if self.UPF_FLAG:
                for upf in self.thread_list:
                    upf.set_dst(tc.smf_ip)

            # 尝试连接amf_client和smf
            try_smf_conn(tc.http2_client)
            ue_lock_manager = UeLockManager(tc.base_ue_info['num'])
            index, send_lock = ue_lock_manager.get_lock()

            # 0号位存 imsi+sessionID 1号位存seid
            ue_args = [None, Queue(), None]
            # seid_dict = {}
            seid_rsp_flag = 0
            tc_report = {
                "result": ""
            }

            # 发送消息循环
            for msg in tc.msg_orders:
                # 发送前 装载回调消息
                if 'msg_responses' in msg:
                    for rsp in msg['msg_responses']:
                        if self.UPF_FLAG:
                            if rsp["ne"] == "UPF":
                                if 'seid_support' in rsp:
                                    # seid_dict[msg['seid_support']] = -1
                                    seid_rsp_flag = 1
                                    self.logger.debug('打开主程local_seid回调')
                                # 未对复数线程服务器做适配
                                for upf in self.thread_list:
                                    upf.set_rsp_task(rsp)
                        if rsp["ne"] == "AMF":
                            self.main_to_amf_list[0].put(('set_rsp', rsp))

                # TODO 检查装载情况 AMF重发开关， UPF建联等待
                # time.sleep(6)  # 等待返回信息装载,等待smf和UPF建联

                # 发送中
                # TODO 多消息的锁机制
                # TODO 非异步发送，需要改成异步
                print('准备发送消息', msg['msg_order'], '-', msg['msg_type'])
                send_lock.acquire()
                req_url = msg['req_url']
                if 'url_rule' in msg:
                    if msg['url_rule'] == 'normal':
                        self.logger.debug("url依赖imsi和pduID")
                        if msg['msg_type'] == PDU_SESSION_MODIFY or PDU_RELEASE_REQ or PDU_RELEASE_RSP or \
                                PDU_RELEASE_COMPLETE:
                            temp = ue_args[0]
                            # print(type(temp[1]), temp[1], type(temp[2]), temp[2], type(req_url), req_url)
                            req_url = req_url.format(int(temp[1]), int(temp[2]))
                            if 'keep_rsp' in msg and msg['keep_rsp']:
                                ue_args[0] = keep_rsp(temp, PDU_SESSION_MODIFY)
                ###############################################################
                if msg['msg_type'] != UPF_SESSION_REPORT_REQ:
                    print('发送前时间', datetime.datetime.now())
                    rsp_id = \
                        tc.http2_client.request(POST, req_url, msg['msg_stream'], msg['msg_header'])
                    # if msg['msg_type'] != INIT_CTX_SETUP_RSP:
                    #     rsp = tc.http2_client.get_response(rsp_id)
                    #     print('rsp消息为', rsp.status, rsp.read(decode_content=False))
                    # if msg['msg_order'] == 2:
                    #     rsp = tc.http2_client.get_response(rsp_id)
                    #     print('发送后时间', datetime.datetime.now(), rsp.read())
                else:
                    if self.UPF_FLAG:
                        target_seid = ue_args[1].get()
                        for upf in self.thread_list:
                            upf.session_report_request(target_seid)

                # 发送后
                # TODO 回调处理
                if 'report_rsp' in msg and msg['report_rsp']:
                    self.logger.debug("进入h2_server回调上报")
                    rsp_var = self.check_h2_server_rsp(10, self.amf_to_main_list[0])
                    if rsp_var is None:
                        break
                    if rsp_var[0] == N1_N2_MSG_SVC:
                        ue_args[0] = rsp_var
                if self.UPF_FLAG:
                    if seid_rsp_flag:
                        for upf in self.thread_list:
                            temp_seid = upf.get_seid_to_main()
                            if temp_seid is None:  # 异常处理
                                tc_report['result'] = 'Failed'
                                continue
                            ue_args[1].put(temp_seid)
                            self.logger.debug("取得seid%d", temp_seid)
                        seid_rsp_flag = 0
                        self.logger.debug('local_seid回调已关闭')
                send_lock.release()

                if 'gap_time' in msg:
                    time.sleep(msg['gap_time'])

                # rsp_var = check_rsp(msg['gap_time'], 0, 5, amf_to_main_list[0], send_lock)
                # if rsp_var[0] == N1_N2_MSG_SVC:
                #     ue_args[0] = rsp_var

                # TODO 非异步现场处理，需要改成异步
                # for upf in thread_list:
                #     upf.reset_rsp_task()  # 清理UPF现场可能导致未完成的消息的上下文消失
                # main_to_amf_list[0].put(('reset_task',))
            # 每个tc重新建联
            tc.http2_client.close()

        # 关闭服务器信号
        if self.UPF_FLAG:
            for upf in self.thread_list:
                upf.stop_thread()
                upf.join(timeout=3)
        for to_amf_q in self.main_to_amf_list:
            to_amf_q.put(('stop_server',))
        for amf in self.process_list:
            amf.join(timeout=3)

        self.logger.info("测试脚本结束")

    def check_h2_server_rsp(self, timeout, target_queue, s_lock=None):
        try:
            res = target_queue.get_nowait(timeout=timeout)
            if s_lock:
                s_lock.release()
            self.logger.info("收到amf server消息")
            return res
        except Empty:
            self.logger.warning("无法从队列%s获得http2 rsp消息", target_queue)
            return None


def get_file_num(path):
    return len(os.listdir(path))


def try_smf_conn(h2_client):
    try:
        h2_client.connect()
    except TimeoutError:
        print("Connect Failed -- Time Out")
        h2_client.close()
        return -1


def config_upf(smf_ip, upf_list):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_socket.bind((get_ip(), D4_PFCP_PORT))
    endpoint = SimpleSocket(sock=raw_socket)
    # 实例化一个upf
    upf_instance = PfcpSkeleton(endpoint, get_ip(), UPF_GW, upf_redis_pool)
    # 设置upf
    upf_instance.set_dst(smf_ip)
    upf_list.append(upf_instance)


def run_nf_server(nf, to_amf_q, to_main_q, type_name=""):
    # print("启动{0!r}服务器中".format(type_name))
    print(f"启动{type_name}服务器中")
    nf.set_rcv_queue(to_amf_q)
    nf.set_send_queue(to_main_q)
    nf.start_server()


def build_amf(p_list, to_sub_list, to_main_list):
    to_amf_queue = mp.Queue()
    to_main_queue = mp.Queue()
    p = mp.Process(target=run_nf_server, args=(SimAmf(), to_amf_queue, to_main_queue, 'amf'))
    p_list.append(p)
    to_sub_list.append(to_amf_queue)
    to_main_list.append(to_main_queue)


def keep_rsp(arg_tuple, msg_type):
    path_list = []
    if not isinstance(arg_tuple[0], list):
        path_list.append(arg_tuple[0])
    path_list.append(msg_type)
    res = (path_list,) + arg_tuple[1:len(arg_tuple)]
    return res
