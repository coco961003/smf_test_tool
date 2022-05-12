import socket


def ipv4_2_val(ip_str):
    num_list = str.split(ip_str, '.')
    res_str = ''
    for index in range(4):
        temp_num = int(num_list[index])
        raw_bit_str = bin(temp_num).split('b')[1]
        i = 8 - len(raw_bit_str)
        res_bit_str = ''
        while i != 0:
            res_bit_str += '0'
            i -= 1
        res_bit_str += raw_bit_str
        res_str += res_bit_str
    res = (int(res_str, base=2), 32)
    # print(res)
    return res


def is_ipv4_legal(ip_str):
    ip_str = str(ip_str)
    ip_str = ip_str.strip()
    if ip_str is "":
        return False
    addr_arr = ip_str.split('.')
    if len(addr_arr) != 4:
        return False
    for i in range(4):
        try:
            x = int(addr_arr[i])
            if 255 >= x >= 0:
                return True
            else:
                return False
        except:
            return False


def trans_int_to_byte(int_num, digit_num=4, type='big'):
    if not isinstance(int_num, int):
        return int_num
    return int_num.to_bytes(digit_num, type)


def get_ip():
    host_name = socket.gethostname()
    host = socket.gethostbyname(host_name)
    return host


def get_h2_server_addr_desc(int_port):
    host = get_ip()
    print('h2 server is at', host, ':', str(int_port))
    res = "tcp:port=%d:interface=%s"
    return res % (int_port, host)


def sum_dict(*args):
    res = {}
    for dict in args:
        if dict:
            for key in dict:
                if key not in res:
                    res[key] = []
                res[key].append(dict[key])
    return res


def get_name(*args):
    if not len(args):
        return ""
    temp = []
    for arg in args:
        temp.append(str(arg))
    res = temp[0]
    for el in temp[1:]:
        res = res + "-" + el
    return res
