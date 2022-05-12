import copy
import json
import logging

from hyper.common.headers import HTTPHeaderMap
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabRequest, FGSMPDUSessionReleaseRequest, \
    FGSMPDUSessionReleaseComplete

from components import json_handler
from src.components import request_combiner
from src.components.nas_builder import get_nas
from components.ngap_builder import build_setup_resp_from_encode, build_pdu_rel_rsp_from_encode, \
    build_xn_switch_req_from_encode, build_handover_required_from_encode, build_handover_req_ack_trans_from_encode, \
    build_pdu_resource_setup_failure_trans
from err.exception import IllegalPathException
from rsc.const import PDU_SESSION_ESTABLISH, CONTENT_TYPE_LOWERCASE, MULTIPART_TYPE, JSON, ACCEPT_ENCODING, GZIP, \
    USER_AGENT, GO_AGENT, D4_PDU_ESTAB_URL, PDU_SESSION_MODIFY, D4_PDU_MODIFY_URL, PDU_RELEASE_REQ, \
    PDU_RELEASE_RSP, PDU_RELEASE_COMPLETE, AMF_RELEASE, D4_AMF_REL_URL, AN_RELEASE, PATH_SWITCH_REQ, HANDOVER_REQ, \
    HANDOVER_REQ_ACK, REGISTRATION_REQ, INIT_CTX_SETUP_RSP, PDU_SESSION_RSC_SETUP_FAILURE_RSP, UPF_SESSION_REPORT_REQ, \
    PFCP
# json
from utils import ipv4_2_val, trans_int_to_byte, sum_dict, get_ip

# TODO 模板相对路径
json_pdu_establish = './rsc/template/json/estab_pdu'
json_pdu_modify = './rsc/template/json/ctx_modify'
json_pdu_rel_req = './rsc/template/json/rel_pdu_req_n1_nas'
json_pdu_rel_rsp = './rsc/template/json/rel_pdu_rsp_n2_ngap'
json_pdu_rel_complete = './rsc/template/json/rel_pdu_complete_n1_nas'
json_amf_rel = './rsc/template/json/rel_due_to_reactivation'
json_an_rel = './rsc/template/json/an_release'
json_path_switch_req = './rsc/template/json/xn_switch'
json_ho_req = './rsc/template/json/handover_required'
json_ho_req_ack = './rsc/template/json/handover_req_ack_trans'
json_regis_req = './rsc/template/json/regis_req'
json_init_ctx_setup_rsp = './rsc/template/json/init_ctx_setup_rsp'
json_pdu_session_rsc_setup_failure_rsp = './rsc/template/json/'


def get_req_url(msg_info):
    if 'url_rule' in msg_info:
        a = msg_info['url_rule']
        if a == "specified":
            return msg_info['url']
        else:
            return get_d4_url(msg_info['msg_type'])
    return msg_info['url'] if 'url' in msg_info else get_d4_url(msg_info['msg_type'])


# TODO 可选消息过滤表
index_list = ('url_rule', 'msg_responses', 'report_rsp', 'gap_time')


def check_and_copy_kw(res_dict, msg_info):
    for index in index_list:
        if index in msg_info:
            res_dict[index] = msg_info[index]


def set_repr_rsp(**kwargs):
    """
        打开report_rsp开关，开启后从回调获取imsi+sessionId
        :param kwargs:
        :return:
        """
    kwargs['res_dict']['report_rsp'] = 1


def set_keep_rsp(**kwargs):
    """
    打开keep_rsp开关，开启后记录获取imsi+sessionId的服务
    :param kwargs:
    :return:
    """
    if 'url_rule' in kwargs['msg_info'] and kwargs['msg_info']['url_rule'] == 'normal':
        kwargs['res_dict']['keep_rsp'] = 1


def get_header(**kwargs):
    req_type = "multi"
    if 'req_type' in kwargs:
        req_type = kwargs['req_type']
    obj = HTTPHeaderMap()
    if req_type == "multi":
        obj.__setitem__(CONTENT_TYPE_LOWERCASE, MULTIPART_TYPE)
    elif req_type == "json":
        obj.__setitem__(CONTENT_TYPE_LOWERCASE, JSON)
    obj.__setitem__(ACCEPT_ENCODING, GZIP)
    obj.__setitem__(USER_AGENT, GO_AGENT)
    kwargs['res_dict']['msg_header'] = obj


def get_json(**kwargs):
    msg_info = kwargs['msg_info']
    path = kwargs['path']
    res_dict = kwargs['res_dict']
    # 如果文件从存在配置文件路径，则直接从路径读取
    if 'json_file_path' in msg_info:
        res_dict['json_msg'] = json_handler.build_json_dict(msg_info['json_file_path'])
    else:
        # 否则根据updates中的更新列表更改数据
        raw_json = open(path)
        template = json.load(raw_json)
        if 'json_updates' in msg_info:
            for i in range(len(msg_info['json_updates'])):
                update_operation = msg_info['json_updates'][i]
                update_path_str = update_operation[0]
                update_val = update_operation[1]
                set_val(template, update_path_str, update_val)
        res_dict['json_msg'] = template


def get_ngap(**kwargs):
    ngap_obj = kwargs['base']()
    msg_info = kwargs['msg_info']
    if "ngap_updates" in msg_info:
        for update in msg_info["ngap_updates"]:
            update_val = dispatch_pre_process(update)
            ngap_obj.set_val_at(update['path'], update_val)
    kwargs['res_dict']['ngap_msg'] = ngap_obj.to_aper()


MSG_TYPE_FLOW_MAPPING = {
    PDU_SESSION_ESTABLISH: (
        (set_repr_rsp, {}),
        (get_header, {}),
        (get_json, {"path": json_pdu_establish}),
        (get_nas, {"base": FGSMPDUSessionEstabRequest()})
    ),
    PDU_SESSION_MODIFY: (
        (set_keep_rsp, {}),
        (get_header, {}),
        (get_json, {"path": json_pdu_modify}),
        (get_ngap, {"base": build_setup_resp_from_encode})
    ),
    PDU_RELEASE_REQ: (
        (set_keep_rsp, {}),
        (get_header, {}),
        (get_json, {"path": json_pdu_rel_req}),
        (get_nas, {"base": FGSMPDUSessionReleaseRequest()})
    ),
    PDU_RELEASE_RSP: (
        (set_keep_rsp, {}),
        (get_header, {}),
        (get_json, {"path": json_pdu_rel_rsp}),
        (get_ngap, {"base": build_pdu_rel_rsp_from_encode})
    ),
    PDU_RELEASE_COMPLETE: (
        (set_keep_rsp, {}),
        (get_header, {}),
        (get_json, {"path": json_pdu_rel_complete}),
        (get_nas, {"base": FGSMPDUSessionReleaseComplete()})
    ),
    AMF_RELEASE: (
        (get_header, {'req_type': 'json'}),
        (get_json, {"path": json_amf_rel})
    ),
    AN_RELEASE: (
        (get_header, {'req_type': 'json'}),
        (get_json, {"path": json_an_rel})
    ),
    PATH_SWITCH_REQ: (
        (get_header, {}),
        (get_json, {"path": json_path_switch_req}),
        (get_ngap, {'base': build_xn_switch_req_from_encode})
    ),
    HANDOVER_REQ: (
        (get_header, {}),
        (get_json, {"path": json_ho_req}),
        (get_ngap, {'base': build_handover_required_from_encode})
    ),
    HANDOVER_REQ_ACK: (
        (get_header, {}),
        (get_json, {"path": json_ho_req_ack}),
        (get_ngap, {'base': build_handover_req_ack_trans_from_encode})
    ),
    REGISTRATION_REQ: (
        (get_header, {'req_type': 'json'}),
        (get_json, {"path": json_regis_req})
    ),
    INIT_CTX_SETUP_RSP: (
        (get_header, {'req_type': 'json'}),
        (get_json, {"path": json_init_ctx_setup_rsp})
    ),
    PDU_SESSION_RSC_SETUP_FAILURE_RSP: (
        (get_header, {}),
        (get_json, {"path": json_pdu_session_rsc_setup_failure_rsp}),
        (get_ngap, {'base': build_pdu_resource_setup_failure_trans})
    )
}


def build_msg(msg_info, imsi_range):
    log = logging.getLogger('BuildMsg')
    log.info('正在处理消息%d,imsi个数%d', msg_info['order'], len(imsi_range))

    # 必填消息赋值
    res_dict = {
        'msg_order': msg_info['order'],
        'msg_type': msg_info['msg_type'],
        # 'msg_timeout': msg_info['client_timeout'] if 'client_timeout' in msg_info else -1,
        # TODO 加新消息的时候记得改
        'req_url': get_req_url(msg_info)
    }
    # 可选消息赋值
    check_and_copy_kw(res_dict, msg_info)

    # TODO 根据消息类型处理 加新消息的时候记得改
    msg_type = msg_info['msg_type']
    for op_tuple in MSG_TYPE_FLOW_MAPPING[msg_type]:
        op_tuple[0](res_dict=res_dict, msg_info=msg_info, **op_tuple[1])

    res = duplicate_msg(imsi_range, res_dict)

    return res


def duplicate_msg(imsi_range, temp_dict):
    res = []
    json_part = None
    nas_part = None
    ngap_part = None

    if 'json_msg' in temp_dict:
        json_part = duplicate_json(imsi_range, temp_dict['json_msg'])
    if 'nas_msg' in temp_dict:
        nas_part = duplicate_nas(imsi_range, temp_dict['nas_msg'])
    if 'ngap_msg' in temp_dict:
        ngap_part = duplicate_ngap(imsi_range, temp_dict['ngap_msg'])

    imsi_parts = sum_dict(json_part, nas_part, ngap_part)
    for raw_parts in imsi_parts.items():
        temp = request_combiner.combine(*raw_parts[1])
        temp_dict_copy = temp_dict.copy()
        temp_dict_copy['imsi'] = raw_parts[0]
        temp_dict_copy['msg_stream'] = temp
        res.append(temp_dict_copy)

    return res


class FormatController:

    def __init__(self):
        self.imsi = ""
        self.__format_op_dict = {
            'imsi_str': self.get_imsi,
            'sim_ip': get_ip,
            'sim_port': self.get_callback_port,
            'mcc': self.get_mcc,
            'mnc': self.get_mnc
        }
        self.log = logging.getLogger('FormatController')

    def get_callback_port(self):
        """暂时不记得端口要填啥"""
        return 56567

    def set_imsi(self, kwargs):
        if 'imsi_str' in kwargs:
            self.imsi = str(kwargs['imsi_str'])
        else:
            self.log.warning('没有找到imsi字符串')

    def get_mcc(self):
        imsi = self.get_imsi()
        mcc = str(imsi)[:3]
        self.log.debug("mcc的值为{0}".format(mcc))
        return mcc

    def get_mnc(self):
        imsi = self.get_imsi()
        mnc = str(imsi)[3:5]
        self.log.debug("mnc的值为{0}".format(mnc))
        return mnc

    def get_imsi(self):
        if self.imsi:
            return self.imsi
        else:
            self.log.warning('imsi不存在')
            return self.imsi

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, "instance"):
            instance = FormatController()
            setattr(cls, "instance", instance)
        return getattr(cls, "instance")

    def handle_fmt_kw(self, parameter):
        try:
            return self.__format_op_dict[parameter]()
        except KeyError:
            self.log.error('{0}不在操作列表中'.format(parameter))
            return None


def get_fmt_dict(*args, **kwargs):
    res = {}
    fmt_ctl = FormatController.get_instance()
    fmt_ctl.set_imsi(kwargs)
    for parameter in args:
        res[parameter] = fmt_ctl.handle_fmt_kw(parameter)
    return res


def duplicate_json(imsi_range, template_json):
    res = {}
    for imsi in imsi_range:
        temp_json = dict.copy(template_json)
        for update_obj in JSON_UPDATE_DICT.items():
            update_path = update_obj[0]
            update_kw = update_obj[1][1:]
            fmt_dict = get_fmt_dict(*update_kw, imsi_str=imsi)  # TODO
            bar_val = update_obj[1][0].format(**fmt_dict)
            try:
                set_val(temp_json, update_path, bar_val)
            except IllegalPathException:
                continue
        res[imsi] = ('json', temp_json)
    return res


JSON_UPDATE_DICT = {
    "supi": ("imsi-{imsi_str!r}", "imsi_str"),
    "smContextStatusUri": (
        "http://{sim_ip!r}:{sim_port!r}/namf-callback/v1/smContextStatus/{imsi_str!r}/1", "sim_ip", "sim_port",
        "imsi_str"),
    "guami/plmnId/mcc": ("{mcc!r}", "mcc"),
    "guami/plmnId/mnc": ("{mnc!r}", "mnc"),
    "servingNetwork/mcc": ("{mcc!r}", "mcc"),
    "servingNetwork/mnc": ("{mnc!r}", "mnc")
}
NAS_UPDATE_DICT = {}
NGAP_UDPATE_DICT = {}


def duplicate_nas(imsi_range, template_nas):
    res = {}
    for imsi in imsi_range:
        temp_nas = template_nas.clone()
        for update in NAS_UPDATE_DICT.items():
            base_copy = temp_nas
            path = update[0]
            path = path.split("/")
            for i in path[:-1]:
                base_copy = base_copy[i]
            base_copy[path[-1]] = update[1]
        res[imsi] = ('nas', temp_nas)
    return res


def duplicate_ngap(imsi_range, template_ngap):
    res = {}
    for imsi in imsi_range:
        temp_ngap = copy.deepcopy(template_ngap)
        for update in NGAP_UDPATE_DICT.items():
            temp_ngap.set_val_at(update[0], update[1])
        res[imsi] = ('ngap', temp_ngap)
    return res


# TODO 默认请求URL字典
d4_url_dict = {
    PDU_SESSION_ESTABLISH: D4_PDU_ESTAB_URL,
    PDU_SESSION_MODIFY: D4_PDU_MODIFY_URL,
    PDU_RELEASE_REQ: D4_PDU_MODIFY_URL,
    PDU_RELEASE_RSP: D4_PDU_MODIFY_URL,
    PDU_RELEASE_COMPLETE: D4_PDU_MODIFY_URL,
    AMF_RELEASE: D4_AMF_REL_URL,
    AN_RELEASE: D4_PDU_MODIFY_URL,
    PATH_SWITCH_REQ: D4_PDU_MODIFY_URL,
    HANDOVER_REQ: D4_PDU_MODIFY_URL,
    HANDOVER_REQ_ACK: D4_PDU_MODIFY_URL,
    REGISTRATION_REQ: D4_PDU_MODIFY_URL,
    INIT_CTX_SETUP_RSP: D4_PDU_MODIFY_URL,
    PDU_SESSION_RSC_SETUP_FAILURE_RSP: D4_PDU_MODIFY_URL,
    UPF_SESSION_REPORT_REQ: PFCP
}


def get_d4_url(type, imsi=None, pdu_id=None):
    if type in d4_url_dict:
        foo = d4_url_dict[type]
        if not imsi or not pdu_id:
            return foo
        else:
            return foo.format(imsi, pdu_id)
    print('查不到消息类型', type, '的默认url')
    return ""


def dispatch_pre_process(update):
    val = update['val']
    if 'pre_process' not in update:
        return val
    for up in update['pre_process']:
        if up == 'ipv4_2_val':
            val = ipv4_2_val(val)
            continue
        if up == 'int_2_byte':
            val = trans_int_to_byte(val)
            continue
    return val


def get_val(target_dict, path_list):
    if path_list:
        return target_dict
    else:
        val = target_dict
    for i in range(len(path_list)):
        index = path_list[i]
        if index in val:
            val = val[index]
        else:
            raise IllegalPathException(path_list)
    return val


def set_val(dict, path_str, val):
    log = logging.getLogger('SetVal')
    log.info("将{path_str!r}的值更改为{val!r}".format(path_str=path_str, val=val))
    path_str_list = path_str.split("/")
    last_key = path_str_list[-1]
    dict = get_val(dict, path_str_list[:-1])
    dict[last_key] = val
