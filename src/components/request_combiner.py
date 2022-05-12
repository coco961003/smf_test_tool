import binascii
import json

from rsc.const import FIRST_BOUNDARY, LAST_BOUNDARY, INNER_BOUNDARY, CONTENT_TYPE4DATA, JSON, CRLF, CONTENT_ID, N1MSG, \
    NAS, NGAP, NGAPIE


def combine(*args):
    """
    基础的报文构成功能，对于修改幅度较小的报文来说并不适合
    :param args: 按顺序排列的元组列表, 每个元组的首个元素是数据类型，第二个是对应数据
    :return: 二进制码流报文
    """
    foo = []
    for i in range(len(args)):
        if args[i][0] == "json":
            if args[i][1]:
                foo.append(json_combine(args[i][1]))
            else:
                continue
        elif args[i][0] == "nas":
            if args[i][1]:
                foo.append(nas_combine(args[i][1]))
            else:
                continue
        elif args[i][0] == "ngap":
            if args[i][1]:
                foo.append(ngap_combine(args[i][1]))
            else:
                continue
        else:
            print("Illegal Type.")
            pass

    res_hex_str = get_hex_str(FIRST_BOUNDARY)
    if len(foo) > 1:
        for i in range(len(foo) - 1):
            res_hex_str += foo[i]
            res_hex_str += get_hex_str(INNER_BOUNDARY)
    if len(foo) >= 1:
        res_hex_str += foo[len(foo) - 1]
    res_hex_str += get_hex_str(LAST_BOUNDARY)
    return binascii.unhexlify(res_hex_str)


def json_combine(raw_json):
    if not raw_json:
        return None
    if isinstance(raw_json, dict):
        raw_json = json.dumps(raw_json)

    ct_type_kv = CONTENT_TYPE4DATA + JSON + CRLF + CRLF

    hex_str_ct_type = get_hex_str(ct_type_kv)
    hex_str_json = get_hex_str(raw_json)

    res = hex_str_ct_type + hex_str_json
    # print(res)
    return res


def nas_combine(nas):
    ct_type_kv = CONTENT_TYPE4DATA + NAS + CRLF
    ct_id_kv = CONTENT_ID + N1MSG + CRLF + CRLF

    hex_str_ct_type = get_hex_str(ct_type_kv)
    hex_str_ct_id = get_hex_str(ct_id_kv)
    hex_str_nas = binascii.hexlify(nas.to_bytes()).decode()

    res = hex_str_ct_type + hex_str_ct_id + hex_str_nas
    # print(res)
    return res


def ngap_combine(ngap):
    ct_type_kv = CONTENT_TYPE4DATA + NGAP + CRLF
    ct_id_kv = CONTENT_ID + NGAPIE + CRLF + CRLF

    hex_str_ct_type = get_hex_str(ct_type_kv)
    hex_str_ct_id = get_hex_str(ct_id_kv)
    hex_str_ngap = binascii.hexlify(ngap).decode()

    res = hex_str_ct_type + hex_str_ct_id + hex_str_ngap
    return res


def get_hex_str(t):
    """
    可encode的对象转16进制字符串
    :param t: 带有encode功能的对象
    :return: 16进制字符串
    """
    return binascii.hexlify(t.encode()).decode()
