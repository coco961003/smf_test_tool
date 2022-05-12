import threading as th


class UeLockManager:
    index_lock = th.Lock()
    index = 0

    def __init__(self, ue_num=0):
        self.lock_dict = {}
        for i in range(ue_num):
            self.lock_dict[i] = th.Lock()

    def get_lock(self, index=None):
        if index:
            if not index < len(self.lock_dict):
                return None
            return self.lock_dict[index]
        res_index = self.__get_index()
        return res_index, self.lock_dict[res_index]

    def __get_index(self):
        self.index_lock.acquire()
        res_index = self.index
        self.index = self.index + 1
        self.index_lock.release()
        return res_index
