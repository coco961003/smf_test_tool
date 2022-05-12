CR = '\r'
LF = '\n'
CRLF = '\r\n'

# 消息类型
# AMF
PDU_SESSION_ESTABLISH = 'pdu_establish'
PDU_SESSION_MODIFY = 'pdu_modify'
PDU_RELEASE_REQ = 'pdu_release_req'
PDU_RELEASE_RSP = 'pdu_release_rsp'
PDU_RELEASE_COMPLETE = 'pdu_release_complete'
AMF_RELEASE = 'amf_release'
AN_RELEASE = 'an_release'
PATH_SWITCH_REQ = 'path_switch_req'
HANDOVER_REQ = 'handover_req'
HANDOVER_REQ_ACK = 'handover_req_ack'
REGISTRATION_REQ = 'regis_req'
INIT_CTX_SETUP_RSP = 'init_ctx_setup_rsp'
PDU_SESSION_RSC_SETUP_FAILURE_RSP = 'pdu_session_resource_setup_failure_rsp'

# UPF
UPF_SESSION_REPORT_REQ = 'upf_session_report_req'

# 默认请求url
D4_PDU_ESTAB_URL = "/nsmf-pdusession/v1/sm-contexts"
D4_PDU_MODIFY_URL = "/nsmf-pdusession/v1/sm-contexts/imsi-{0!r}-{1!r}/modify"
D4_AMF_REL_URL = "/nsmf-pdusession/v1/sm-contexts/imsi-{0!r}-{1!r}/release"

# 请求方式
POST = 'POST'
GET = 'GET'

# 服务名
N1_N2_MSG_SVC = "n1_n2_msg"
SM_CTX_CB_SVC = "sm_ctx_cb"

PFCP = "PFCP"
PATH = 'path'
ACCEPT_ENCODING = 'accept-encoding'
GZIP = 'gzip'
USER_AGENT = 'user-agent'
GO_AGENT = 'Go-http-client/2.0'
CONTENT_TYPE_LOWERCASE = 'content-type'
CONTENT_TYPE4DATA = 'Content-Type:'
AUTHORITY = ':authority'
MULTIPART_TYPE = 'multipart/related;boundary=----Boundary'
BOUNDARY = '----Boundary'
MEDIA_TYPE = 'Media type'
NAS = 'application/vnd.3gpp.5gnas'
JSON = 'application/json'
NGAP = 'application/vnd.3gpp.ngap'
CONTENT_ID = 'Content-Id:'
CONTENT_ID_LOWERCASE = 'content-id'
N1MSG = 'n1msg'
NGAPIE = 'ngapie'

# 边界符
FIRST_BOUNDARY = '------Boundary\r\n'
INNER_BOUNDARY = '\r\n------Boundary\r\n'
LAST_BOUNDARY = '\r\n------Boundary--'
