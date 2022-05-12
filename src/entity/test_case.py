import hyper

from components import msg_factory


def get_order(msg_dict):
    return msg_dict['msg_order']


class TestCase(object):
    msg_orders = {}  # 存放顺序发送的消息列表

    def __init__(self, config):
        self.http2_client = hyper.HTTP20Connection(config['smf_ip'], config['smf_port'])
        self.smf_ip = config['smf_ip']
        self.smf_port = config['smf_port']
        self.base_ue_info = config['ue']
        ue_num = config['ue']['num']
        imsi_int = int(config['ue']['imsi'])
        self.imsi_range = range(imsi_int, imsi_int + ue_num)
        self.raw_config = config

    def process_config(self):
        if 'msgs' not in self.raw_config:
            return
        msg_num = len(self.raw_config['msgs'])

        for i in range(msg_num):
            # 提取配置信息
            msg_dict = msg_factory.build_msg(self.raw_config['msgs'][i], self.imsi_range)  # 配置数据转码流
            for imsi_msg in msg_dict:
                self.init_imsi_list(imsi_msg['imsi'])
                self.set_imsi_val(imsi_msg)
        self.sort_orders()

    def init_imsi_list(self, imsi_num):
        if imsi_num not in self.msg_orders:
            self.msg_orders[imsi_num] = []

    def set_imsi_val(self, imsi_msg):
        self.msg_orders[imsi_msg['imsi']].append(imsi_msg)

    def sort_orders(self):
        for imsi_msg in self.msg_orders.values():
            imsi_msg.sort(key=get_order)
