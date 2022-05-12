from enum import Enum


class PfcpMsgEnum(Enum):
    heartbeat_request = 1
    heartbeat_response = 2
    pfd_management_request = 3
    pfd_management_response = 4
    association_setup_request = 5
    association_setup_response = 6
    association_update_request = 7
    association_update_response = 8
    association_release_request = 9
    association_release_response = 10
    version_not_supported_response = 11
    node_report_request = 12
    node_report_response = 13
    session_set_deletion_request = 14
    session_set_deletion_response = 15
    session_establishment_request = 50
    session_establishment_response = 51
    session_modification_request = 52
    session_modification_response = 53
    session_deletion_request = 54
    session_deletion_response = 55
    session_report_request = 56
    session_report_response = 57


PFCPmessageTypeDict = {
    1: "PFCP Heartbeat Request",
    2: "PFCP Heartbeat Response",
    3: "PFCP Pfd Management Request",
    4: "PFCP Pfd Management Response",
    5: "PFCP Association Setup Request",
    6: "PFCP Association Setup Response",
    7: "PFCP Association Update Request",
    8: "PFCP Association Update Response",
    9: "PFCP Association Release Request",
    10: "PFCP Association Release Response",
    11: "PFCP Version Not Supported Response",
    12: "PFCP Node Report Request",
    13: "PFCP Node Report Response",
    14: "PFCP Session Set Deletion Request",
    15: "PFCP Session Set Deletion Response",
    50: "PFCP Session Establishment Request",
    51: "PFCP Session Establishment Response",
    52: "PFCP Session Modification Request",
    53: "PFCP Session Modification Response",
    54: "PFCP Session Deletion Request",
    55: "PFCP Session Deletion Response",
    56: "PFCP Session Report Request",
    57: "PFCP Session Report Response",
}
