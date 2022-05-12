class IllegalPathException(Exception):
    def __init__(self, *args):
        self.path_list = args

    def __str__(self):
        return repr(self.path_list)
