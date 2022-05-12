import threading


class UserEquipment:
    imsi = -1
    session_id = -1
    send_lock = threading.Lock()
    seid = -1
