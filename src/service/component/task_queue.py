from queue import Queue

DEFAULT = 'd4'


class TaskQueue:
    check_flag = False

    def __init__(self):
        self.reset_dict()

    def init_dict_by_key(self, key, size=5):
        self.dict[key] = Queue(maxsize=size)

    def reset_dict(self):
        self.dict = {}
        self.init_dict_by_key(DEFAULT)

    def set_queue_item(self, key, item):
        self.check_key(key)
        self.dict[key].put(item)

    def get_queue_item(self, key):
        self.check_key(key)
        return self.dict[key].get()

    def check_key(self, key):
        if key not in self.dict:
            if self.check_flag is False:
                self.init_dict_by_key(key)
            else:
                return None
