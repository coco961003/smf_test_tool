from components import json_handler


def preprocess_nas_dict(nas_val_dict):
    if 'IntegrityProtMaxDataRate' in nas_val_dict:
        key = 'IntegrityProtMaxDataRate'
        arr = nas_val_dict[key]['V'].split('/')
        ul_num_byte = int(arr[0]).to_bytes(length=1, byteorder='big', signed=False)
        dl_num_byte = int(arr[1]).to_bytes(length=1, byteorder='big', signed=False)
        nas_val_dict[key]['V'] = ul_num_byte + dl_num_byte


def get_nas(**kwargs):
    msg_info = kwargs['msg_info']
    base = kwargs['base']
    res_dict = kwargs['res_dict']
    if 'nas_file_path' in msg_info:
        nas_val_dict = json_handler.build_json_dict(msg_info['nas_file_path'])
        preprocess_nas_dict(nas_val_dict)
        base.set_val(nas_val_dict)
    if 'nas_updates' in msg_info:
        for update_tuple in msg_info['nas_updates']:
            base_copy = base
            path = update_tuple[0]
            path = path.split("/")
            for i in path[:-1]:
                base_copy = base_copy[i]
            base_copy[path[-1]] = update_tuple[1]
    res_dict['nas_msg'] = base
