import json

from rsc.const import CRLF, CONTENT_TYPE_LOWERCASE, CONTENT_ID_LOWERCASE, JSON


class Multipart:

    def __init__(self, raw_content):
        # for el in content_arr:
        kw_arr = raw_content.split(CRLF.encode())
        for kw in kw_arr:
            if len(kw):
                kw_arr = kw.split(':'.encode())
                if len(kw_arr) == 2:
                    key, value = kw_arr
                elif len(kw_arr) == 1:
                    key = None
                    value = kw_arr[0]
                else:
                    key = None
                    value = kw
                ki = key.decode().lower() if key else None
                if CONTENT_TYPE_LOWERCASE == ki:
                    self.content_type = value.decode()
                    continue
                if CONTENT_ID_LOWERCASE == ki:
                    self.content_id = value.decode()
                    continue
                if ki is None:
                    self.raw_data_content = value
                    if self.content_type and self.content_type == JSON:
                        self.data_content = json.loads(self.raw_data_content.decode())
