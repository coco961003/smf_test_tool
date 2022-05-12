import json
import logging
import os
import platform
import threading
import time
import uuid
from datetime import datetime
from queue import Queue, Empty

import redis
from scapy.all import sendp
from scapy.contrib.pfcp import IE_NodeId, IE_FSEID, IE_PDR_Id, IE_FTEID, IE_CPFunctionFeatures, IE_Cause, \
    IE_UPFunctionFeatures, \
    IE_UsageReport_SDR, IE_URR_Id, IE_UR_SEQN, IE_UsageReportTrigger, IE_StartTime, IE_EndTime, IE_TimeOfFirstPacket, \
    IE_TimeOfLastPacket, IE_VolumeMeasurement, IE_RecoveryTimeStamp, IE_CreatedPDR, IE_ReportType, \
    IE_DownlinkDataReport, \
    IE_DownlinkDataServiceInformation, CauseValues
from scapy.contrib.pfcp import PFCP, PFCPHeartbeatRequest, PFCPHeartbeatResponse, \
    PFCPAssociationSetupRequest, PFCPAssociationUpdateRequest, PFCPAssociationReleaseRequest, \
    PFCPAssociationSetupResponse, PFCPAssociationUpdateResponse, PFCPAssociationReleaseResponse, \
    PFCPSessionEstablishmentResponse, PFCPSessionModificationResponse, \
    PFCPSessionDeletionResponse, \
    PFCPSessionReportRequest, PFCPSessionReportResponse
from scapy.layers.inet import Ether, IP, UDP
from scapy.layers.l2 import arping

from components.pfcp_builder import build_pfcp_session_establishment_response, build_pfcp_session_modification_response
# 被测SMF需要设置的参数
from src.service.upf.pfcp_define import PfcpMsgEnum, PFCPmessageTypeDict
from utils import is_ipv4_legal

PFCP_CP_IP_V4 = "172.17.0.80"
CP_GW = '172.17.3.254'

# 模拟ue需要设置的参数
UE_IP_START = '112.1.0.1'
UE_IP_NUMBER = 5

DEFAULT_PFCP_PORT = 8805
DEFAULT_RETRY_PERIOD = 5


###########
# 静态方法 #
###########
# 获取时间戳
def get_timestamp():
    return int((datetime.now() - datetime(1900, 1, 1)).total_seconds())


# 通过arp请求获取对应IP的mac
def getmacfromarp(gw):
    ans = arping(gw)
    if len(ans[0]) == 1:
        mac = ans[0].res[0][1][Ether].src
        print("mac: %s " % mac)
        return mac
    return None


# 获取IP的mac
def getmacfromsystem(gw):
    cmd = "arp -n"
    pt = platform.system().lower()
    if pt == "windows":
        cmd = 'arp -a'
    res = os.popen(cmd).read()
    i1 = res.find(gw)
    if i1 == -1:
        print("no find arp mac , then try to arp\n")
        return getmacfromarp(gw)
    i2 = i1 + len(gw)
    if pt == "linux":
        i2 = res.find("ether", i2)
        i2 += len('ether')
    while res[i2].isspace():
        i2 += 1
    if i2 + 17 < len(res):
        return res[i2:i2 + 17].replace('-', ':', 5)
    print("no find arp mac again, then try to arp\n")
    return getmacfromarp(gw)


class PfcpSkeleton(threading.Thread):
    teid_counter = 0
    seq = 1

    pfcp_cp_ip = None
    # response_task = {}
    smf_ip = "127.0.0.1"
    LOCAL_IE_FLAG = 1
    rsp_list = Queue()
    run_flag = True

    # task_num = 0
    # task_num_lock = threading.Lock()

    def __init__(self, sk, upf_ip, upf_gw, redis_connection_pool=None):
        super(PfcpSkeleton, self).__init__()
        self.__logger = logging.getLogger('UPF')
        self.__logger.debug("Initialize Start!")
        self.__pfcp_up_ip = upf_ip
        # 监听的端口
        self.endpoint = sk
        self.nodeId = IE_NodeId(ipv4=self.__pfcp_up_ip)
        self.src = self.__pfcp_up_ip
        self.mac = getmacfromsystem(upf_gw)
        if self.mac is None:
            self.__logger.warning("Mac is None.")
        if redis_connection_pool:
            self.redis_buffer = redis.Redis(connection_pool=redis_connection_pool)
        else:
            self.redis_buffer = redis.Redis(host='172.17.0.44', password='123456', db=9)

    def get_seid_to_main(self, current=1):
        self.__logger.debug("upf第%d次尝试获取生成的local_seid", current)
        try:
            seid = self.rsp_list.get(timeout=1)
            return seid
        except Empty:
            if current >= 3:
                self.__logger.warning("获取local_seid失败")
                return None
            self.get_seid_to_main(current + 1)

    def set_dst(self, smf_ip):
        if self.smf_ip != smf_ip:
            self.smf_ip = smf_ip

    def __process_ue_task(self, rsp):
        name = rsp['msg_type'] + "-" + rsp['ue_ip']
        self.redis_buffer.rpush(name, json.dumps(rsp))

    def __process_task_queue(self, rsp):
        name = rsp['msg_type']
        self.redis_buffer.rpush(name, json.dumps(rsp))

    # 响应任务设置选择
    def set_rsp_task(self, response):
        self.__logger.info("收到%s的回调任务设置", response['msg_type'])
        if "ue_ip" in response and is_ipv4_legal(response["ue_ip"]):
            self.__process_ue_task(response)
        else:
            self.__process_task_queue(response)

    # 获取任务
    # 两次分布式查询的性能损耗
    def get_rsp_task(self, type, ue_ip=None):
        res = None
        if ue_ip:
            name = type + '-' + ue_ip
            res = self.redis_buffer.lpop(name)
        if not res:
            res = self.redis_buffer.lpop(type)
        return res

    def stop_thread(self):
        self.__logger.info("开始结束upf线程")
        self.run_flag = False

    def seid(self):
        """
        此方法生成的UUID当作seid可能会因SEID层面不同导致浪费
        :return:
        """
        return uuid.uuid4().int & (1 << 64) - 1

    def teid(self):
        self.teid_counter = self.teid_counter + 1
        return self.teid_counter

    # def ie_ue_ip_address(self, SD=0):
    #     return IE_UE_IP_Address(ipv4=self.ue_ip, V4=1, SD=SD)

    def ie_fseid(self, fd):
        return IE_FSEID(ipv4=self.__pfcp_up_ip, v4=1, seid=fd)

    def ie_fteid(self, td):
        return IE_FTEID(ipv4=self.__pfcp_up_ip, V4=1, TEID=td)

    def heartbeat_request(self):
        self.chat(PFCPHeartbeatRequest(IE_list=[
            IE_RecoveryTimeStamp(timestamp=get_timestamp())
        ]))

    def heartbeat_response(self, seq=1):
        self.chat(PFCPHeartbeatResponse(IE_list=[
            IE_RecoveryTimeStamp(timestamp=get_timestamp())
        ]), seq=seq)

    def associate_setup_request(self):
        self.chat(PFCPAssociationSetupRequest(IE_list=[
            self.nodeId,
            IE_RecoveryTimeStamp(timestamp=get_timestamp)
        ]))

    def associate_setup_response(self, seq=1):
        self.chat(PFCPAssociationSetupResponse(IE_list=[
            self.nodeId,
            IE_Cause(cause=CauseValues[1]),
            IE_RecoveryTimeStamp(timestamp=get_timestamp()),
            IE_UPFunctionFeatures()
        ]), seq=seq)

    def associate_update_request(self):
        self.chat(PFCPAssociationUpdateRequest(IE_list=[
            self.nodeId,
            IE_CPFunctionFeatures()
        ]))

    def associate_update_response(self, seq=1):
        self.chat(PFCPAssociationUpdateResponse(IE_list=[
            self.nodeId,
            IE_Cause(cause=CauseValues[1]),
            IE_RecoveryTimeStamp(timestamp=get_timestamp()),
            IE_UPFunctionFeatures()
        ]), seq)

    def associate_release_request(self):
        self.chat(PFCPAssociationReleaseRequest(IE_list=[
            self.nodeId
        ]))

    def associate_release_response(self, seq=1):
        self.chat(PFCPAssociationReleaseResponse(IE_list=[
            self.nodeId,
            IE_Cause(cause=CauseValues[1]),
        ]), seq=seq)

    # def session_establish_request(self, local_seid):
    #     self.chat(PFCPSessionEstablishmentRequest(IE_list=[
    #         self.nodeId,
    #         self.ie_fseid(local_seid),
    #         IE_CreatePDR(IE_list=[
    #             IE_PDR_Id(id=1),
    #             IE_Precedence(precedence=255),
    #             IE_PDI(IE_list=[
    #                 IE_SourceInterface(interface="Access"),
    #                 IE_FTEID(CHID=1, CH=1, V4=1, choose_id=1),
    #                 IE_SDF_Filter(
    #                     BID=1, FD=1, sdf_filter_id=1,
    #                     flow_description="permit out ip from any to assigned"),
    #                 IE_QFI(QFI=5)
    #             ]),
    #             IE_OuterHeaderRemoval(),
    #             IE_FAR_Id(id=1),
    #             IE_QER_Id(id=1),
    #             IE_QER_Id(id=2)
    #         ]),
    #         IE_CreatePDR(IE_list=[
    #             IE_PDR_Id(id=2),
    #             IE_Precedence(precedence=255),
    #             IE_PDI(IE_list=[
    #                 IE_SourceInterface(interface="Core"),
    #                 self.ie_ue_ip_address(self.context[local_seid]['ue_ip'], SD=1),
    #                 IE_SDF_Filter(
    #                     BID=1, sdf_filter_id=1
    #                 ),
    #                 IE_QFI(QFI=5)
    #             ]),
    #             IE_FAR_Id(id=2),
    #             IE_QER_Id(id=1),
    #             IE_QER_Id(id=2)
    #         ]),
    #         IE_CreateFAR(IE_list=[
    #             IE_FAR_Id(id=1),
    #             IE_ApplyAction(FORW=1),
    #             IE_ForwardingParameters(IE_list=[
    #                 IE_DestinationInterface(interface="Core")
    #             ]),
    #         ]),
    #         IE_CreateFAR(IE_list=[
    #             IE_FAR_Id(id=2),
    #             IE_ApplyAction(NOCP=1, BUFF=1),
    #             IE_BAR_Id(id=1)
    #         ]),
    #         IE_Create_BAR(IE_list=[
    #             IE_BAR_Id(id=1)
    #         ]),
    #         IE_CreateQER(IE_list=[
    #             IE_QER_Id(id=1),
    #             IE_GateStatus(ul="OPEN", dl="OPEN"),
    #             IE_MBR(ul=2000000, dl=2000000)
    #         ]),
    #         IE_CreateQER(IE_list=[
    #             IE_QER_Id(id=2),
    #             IE_GateStatus(ul="OPEN", dl="OPEN"),
    #             IE_MBR(ul=2000000, dl=2000000),
    #             IE_QFI(QFI=5)
    #         ])
    #     ]), seid=self.context[local_seid]['remote_seid'])

    def get_seid_teid(self, remote_seid):
        local_seid = self.seid()
        local_teid = self.teid()
        # self.context[local_seid] = (remote_seid, local_teid)
        self.redis_buffer.hset(
            name=local_seid,
            mapping={"remote_seid": remote_seid, "local_teid": local_teid}
        )
        return local_seid, local_teid

    # def check_ctx(self, ie_fseid):
    #     ip = ie_fseid.ipv4 if ie_fseid.ipv4 else ie_fseid.ipv6
    #     key = ip + "-" + str(ie_fseid.seid)
    #     if self.context[key] == ():
    #         return self.get_seid_teid(key)
    #     else:
    #         return self.context[key]

    def session_establish_response(self, pfcp, seq=1):
        type_desc = PfcpMsgEnum.session_establishment_response.name
        remote_seid = pfcp.payload.IE_list[1].seid
        local_seid = pfcp.seid
        ue_ipv4 = pfcp.payload.IE_list[3].IE_list[2].IE_list[1].ipv4
        # ue_ipv6 = pfcp.payload.IE_list[3].IE_list[2].IE_list[1].ipv6

        if local_seid:
            remote_seid, local_teid = self.redis_buffer.get(local_seid)
            self.__logger.warning('传入的local_seid为0')
        else:
            local_seid, local_teid = self.get_seid_teid(remote_seid)

        # IE列表与监听比较
        d4_ie_list = [
            self.nodeId,
            IE_Cause(cause=CauseValues[1]),
            # self.ie_fseid(self.context[cp_seid]['remode_seid']),
            self.ie_fseid(local_seid),
            IE_CreatedPDR(IE_list=[
                IE_PDR_Id(id=1),
                self.ie_fteid(local_teid)
            ]),
        ]

        rsp_task = self.get_rsp_task(type_desc, ue_ipv4)

        if rsp_task:
            rsp_task = json.loads(rsp_task)

        spec_ie_list = build_pfcp_session_establishment_response(
            rsp_task
        )

        if self.LOCAL_IE_FLAG and spec_ie_list:
            spec_ie_list.append(self.ie_fseid(local_seid))
            spec_ie_list.append(IE_CreatedPDR(IE_list=[
                IE_PDR_Id(id=1),
                self.ie_fteid(local_teid)
            ]))

        is_report = False
        if rsp_task:
            is_report = rsp_task['seid_support'] if 'seid_support' in rsp_task else False

        if is_report:
            self.rsp_list.put(local_seid)
            self.__logger.info("upf上报seid%d", local_seid)

        self.chat(
            PFCPSessionEstablishmentResponse(
                IE_list=spec_ie_list if spec_ie_list != [] else d4_ie_list
            ),
            seq=seq,
            # seid=self.context[cp_seid]['remote_seid']
            seid=remote_seid
        )

    # def session_modification_request(self, local_seid, gNB_teid):
    #     self.chat(PFCPSessionModificationRequest(IE_list=[
    #         IE_UpdateFAR(IE_list=[
    #             IE_FAR_Id(id=2),
    #             IE_ApplyAction(FORW=1),
    #             IE_UpdateForwardingParameters(IE_list=[
    #                 IE_DestinationInterface(interface="Access"),
    #                 IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=gNB_teid, ipv4=gNB_ADDR),
    #             ])
    #         ])
    #     ]), seid=self.context[local_seid]['remote_seid'])

    def get_remote_seid(self, local_seid):
        self.__logger.debug('尝试获取local_seid%s的remote_seid', local_seid)
        res = self.redis_buffer.hget(local_seid, key='remote_seid')
        res = int(res)
        return res

    def session_modification_response(self, local_seid, seq=1):
        type_desc = PfcpMsgEnum.session_modification_response.name
        d4_ie_list = [
            IE_Cause(cause=CauseValues[1]),
        ]

        spec_ie_list = build_pfcp_session_modification_response(
            self.get_rsp_task(type_desc)
        )

        self.chat(PFCPSessionModificationResponse(
            IE_list=spec_ie_list if spec_ie_list != [] else d4_ie_list
        ), seq=seq, seid=self.get_remote_seid(local_seid))

    def session_deletion_request(self, local_seid):
        pass
        # self.chat(PFCPSessionDeletionRequest(IE_list=[
        # ]), seid=self.context[local_seid]['remote_seid'])

    def session_deletion_response(self, local_seid, seq=1):
        print('upf local_seid', local_seid)
        d4_ie_list = [
            IE_Cause(cause=CauseValues[1]),
            IE_UsageReport_SDR(IE_list=[
                IE_URR_Id(id=1),
                IE_UR_SEQN(number=0),
                IE_UsageReportTrigger(TERMR=1),
                IE_StartTime(timestamp=0),
                IE_EndTime(timestamp=1),
                IE_TimeOfFirstPacket(timestamp=1),
                IE_TimeOfLastPacket(timestamp=1),
                IE_VolumeMeasurement(
                    DLVOL=1, ULVOL=1, TOVOL=1, downlink=1, uplink=1, total=2
                )
            ])
        ]
        not_found_list = [
            IE_Cause(cause=CauseValues[65])
        ]
        # 判断local_seid是否存在在上下文
        exist_flag = self.redis_buffer.exists(local_seid)
        ie_list = not_found_list if not exist_flag else d4_ie_list
        self.chat(PFCPSessionDeletionResponse(
            IE_list=ie_list
        ), seq=seq, seid=self.get_remote_seid(local_seid) if exist_flag else None)

    def session_report_request(self, local_seid, seq=1):
        self.chat(PFCPSessionReportRequest(IE_list=[
            IE_ReportType(DLDR=1),
            IE_DownlinkDataReport(IE_list=[
                IE_PDR_Id(id=2),
                IE_DownlinkDataServiceInformation(
                    spare_1=0,
                    QFII=1,
                    PPI=1,
                    spare_2=0,
                    ppi_val=0,
                    spare_3=0,
                    qfi_val=5
                )
            ])
        ]), seq=seq, seid=self.get_remote_seid(local_seid))

    def session_report_response(self, local_seid, seq=1):
        self.chat(PFCPSessionReportResponse(IE_list=[
            IE_Cause(cause=CauseValues[1]),
        ]), seq, seid=self.get_remote_seid(local_seid))

    # 发送函数；拼接数据包，并通过二层转发出去
    # TODO 封装一层定时器
    def chat(self, pkt, dst=None, seq=None, seid=None):
        self.__logger.info("REQ: %r" % pkt)
        sendp(Ether(dst=self.mac) /
              IP(src=self.src, dst=dst if dst else self.smf_ip) /
              UDP(sport=8805, dport=8805) /
              PFCP(version=1, S=0 if seid is None else 1, seid=0 if seid is None else seid,
                   seq=self.seq if seq is None else seq) /
              pkt, verbose=0,
              # socket=self.endpoint
              )
        if seq is None:
            self.seq += 1

    # ——————以下为主要逻辑部分——————

    def try_associate_setup(self):
        try:
            self.associate_setup_request()
            self.__logger.info('Associate success')
        except BaseException:
            self.__logger.info('Associate with SMF failed. Try again.')
            time.sleep(DEFAULT_RETRY_PERIOD)
            self.try_associate_setup()

    # def try_associate_response(self):
    #     print("Enter try_associate_response")
    #     while not self.__is_associated:
    #         pkt = self.endpoint.sniff(count=1, timeout=2)
    #         if len(pkt) == 0:
    #             continue
    #         temp_pkt = PFCP(bytes(pkt[0]))
    #         if temp_pkt.message_type == PfcpMsgEnum.association_setup_request.value:
    #             self.associate_setup_response()
    #             self.__is_associated = True

    def upf_run(self):
        while self.run_flag:
            pkt = self.endpoint.sniff(lfilter=lambda pkt: "PFCP (v1) Header" in PFCP(bytes(pkt)), count=1)
            pfcp = PFCP(bytes(pkt[0]))
            msg_type = int(pfcp.message_type)
            print("Receive msg_type = %s" % PFCPmessageTypeDict[msg_type])
            if msg_type == PfcpMsgEnum.heartbeat_request.value:
                self.heartbeat_response(pfcp.seq)
            elif msg_type == PfcpMsgEnum.heartbeat_response.value:
                pass
            elif msg_type == PfcpMsgEnum.association_setup_request.value:
                print("Send msg_type = PFCP Associate Setup Response\n")
                self.associate_setup_response(pfcp.seq)
            elif msg_type == PfcpMsgEnum.association_setup_response.value:
                pass
            elif msg_type == PfcpMsgEnum.association_update_request.value:
                pass
            elif msg_type == PfcpMsgEnum.association_update_response.value:
                pass
            elif msg_type == PfcpMsgEnum.association_release_request.value:
                pass
            elif msg_type == PfcpMsgEnum.association_release_response.value:
                pass
            elif msg_type == PfcpMsgEnum.session_establishment_request.value:
                print("Send msg_type = PFCP Session Establishment Request\n")
                self.session_establish_response(pfcp)
            elif msg_type == PfcpMsgEnum.session_establishment_response.value:
                pass
            elif msg_type == PfcpMsgEnum.session_modification_request.value:
                print("Send msg_type = PFCP Session Modification Response\n")
                print("modify rsp start", datetime.now())
                self.session_modification_response(pfcp.seid)
                print("modify rsp finish", datetime.now())
                # send data
                # uplink_event.set()
                # downlink_event.set()
            elif msg_type == PfcpMsgEnum.session_modification_response.value:
                pass
            elif msg_type == PfcpMsgEnum.session_deletion_request.value:
                print("Send msg_type = PFCP Session Modification Response\n")
                self.session_deletion_response(pfcp.seid)
            elif msg_type == PfcpMsgEnum.session_deletion_response.value:
                pass
            elif msg_type == PfcpMsgEnum.session_report_request.value:
                pass
            elif msg_type == PfcpMsgEnum.session_report_response.value:
                pass
            elif msg_type == PfcpMsgEnum.session_set_deletion_request.value:
                pass
            elif msg_type == PfcpMsgEnum.session_set_deletion_response.value:
                pass
            else:
                print("msg type is undefine\n")

    def run(self):
        # 主动建联，放进临时线程
        # self.try_associate_setup()
        # self.try_associate_response()
        print("upf running!")
        self.upf_run()

# 根据起始ue ip和个数，生成ue ip列表
# def getuelist(ue_ip_start, number):
#     i1 = ue_ip_start.find('.')
#     ip_first = ue_ip_start[:i1]
#     i2 = ue_ip_start.find('.', i1 + 1)
#     ip_second = ue_ip_start[i1 + 1:i2]
#     i3 = ue_ip_start.find('.', i2 + 1)
#     ip_third = ue_ip_start[i2 + 1:i3]
#     ip_fourth = ue_ip_start[i3 + 1:]
#
#     ue_ip_list = []
#     ip_int_fourth = int(ip_fourth)
#     ip_int_third = int(ip_third)
#     ip_int_second = int(ip_second)
#     ip_int_first = int(ip_first)
#
#     while number >= 0:
#         ip_max_fourth = ip_int_fourth + number
#         if ip_max_fourth > 255:
#             ip_max_fourth = 255
#         for i in range(ip_int_fourth, ip_max_fourth):
#             ue_ip_list.append(ip_first + "." + ip_second + '.' + ip_third + '.' + str(i))
#         number -= 255 - ip_int_fourth
#         ip_int_fourth = 0
#         ip_int_third = ip_int_third + 1
#         if ip_int_third > 254:
#             ip_int_third = 0
#             ip_int_second += 1
#             if ip_int_second > 254:
#                 ip_int_second = 0
#                 ip_int_first += 1
#                 if ip_int_first > 254:
#                     break
#         ip_third = str(ip_int_third)
#         ip_second = str(ip_int_second)
#         ip_first = str(ip_int_first)
#
#     return ue_ip_list


# 此线程用于接收所有PFCP消息
# def do_thread_pfcp(sk):
#     while dopfcp_cnt.empty():
#         pass
#     while not dopfcp_cnt.empty():
#         pkt = sk.sniff(count=1, timeout=2)
#         if len(pkt) == 0:
#             continue
#         pfcp_header = PFCP(bytes(pkt[0]))['PFCP (v1) Header']
#         if pfcp_header.message_type == 1:
#             # heart beat request
#             pfcp_client.heartbeat_response()
#         elif pfcp_header.message_type == 2:
#             # heart beat response，暂不处理
#             pass
#         else:
#             # 其他PFCP消息放入队列，以便主线程获取
#             dopfcp_msg.put(pkt[0])
#         # 根据全局配置参数，是否主动发送Heart Beat Request
#         if Send_Heart_Beat:
#             pfcp_client.heartbeat_request()
