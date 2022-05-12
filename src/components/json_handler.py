import json

from rsc.const import CRLF


def build_json_str(file_path_str):
    """

    :param file_path_str: json文件路径
    :return: json文件的str对象
    """
    try:
        target_file = open(file_path_str, mode='r', buffering=-1, encoding='UTF-8',
                           newline=CRLF)
    except OSError:
        print('json文件', file_path_str, '不存在')
        return None
    json_obj = target_file.read(-1)
    target_file.close()
    # 去换行空格
    json_obj = de_format(json_obj)
    return json_obj


def build_json_dict(file_path_str):
    """

    :param file_path_str: json文件路径
    :return: json文件的str对象
    """
    try:
        target_file = open(file_path_str, mode='r', buffering=-1, encoding='UTF-8',
                           newline=CRLF)
    except OSError:
        print('json文件', file_path_str, '不存在')
        return None
    return json.load(target_file)


def de_format(ctx):
    return ctx.replace(CRLF, "").replace(" ", "")
