from binascii import unhexlify

from entity.multipart import Multipart
from rsc.const import BOUNDARY, FIRST_BOUNDARY, LAST_BOUNDARY, INNER_BOUNDARY, JSON


def preprocess_multi_rsp(request):
    arr = decode_rsp_byte(request.content.read(), get_content_type(request.requestHeaders))
    res = None
    for el in arr:
        mp_obj = Multipart(el)
        if mp_obj.content_type == JSON:
            res = mp_obj
            break
    return res


def decode_rsp_byte(byte_stream, content_type):
    print('解码content_type为', content_type)
    hex_content = byte_stream.hex()
    byte_content = unhexlify(hex_content)
    boundary = content_type.split('=', maxsplit=1)[1]
    if boundary != BOUNDARY:
        print("警告，边界字符串不是", BOUNDARY)
        return None
    # 注意，替换第一个边界的时候会把内部边界也给替换掉，所以只替换第一个
    content_arr = byte_content.replace(FIRST_BOUNDARY.encode(), b'', 1) \
        .replace(LAST_BOUNDARY.encode(), b'') \
        .split(INNER_BOUNDARY.encode())
    return content_arr


def get_content_type(headers):
    foo = headers.getRawHeaders(name='content-type')
    return foo[0]
