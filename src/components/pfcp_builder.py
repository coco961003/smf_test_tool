from scapy.contrib.pfcp import IEType, IE_NodeId, IE_Cause, IE_FSEID, IE_CreatedPDR, IE_PDR_Id, IE_FTEID


def ie_dict(foo_dict, num):
    f'''
    
    :param foo_dict: 传入的ie列表，通常是配置中upf的回复ie列表
    :param num: 三方库{IEType}的索引数字
    :return: 存在返回值，不存在返回None
    '''
    res = foo_dict[IEType[num]] if IEType[num] in foo_dict else None
    return res


def build_pfcp_session_establishment_response(rsp_task):
    res_list = []
    if not rsp_task:
        return res_list
    ies_dict = rsp_task['IEs_dict']
    # mand = [
    #            PFCPIEType.NodeID.value,
    #            PFCPIEType.Cause.value
    #        ],
    # opt = [
    #     PFCPIEType.OffendingIE.value,
    #     PFCPIEType.FSEID.value,
    #     PFCPIEType.CreatePDR.value,
    #     PFCPIEType.LoadControlInformation.value,
    #     PFCPIEType.OverloadControlInformation.value,
    #     PFCPIEType.FQCSID.value,
    #     PFCPIEType.FailedRuleID.value,
    #     PFCPIEType.CreatedTrafficEndpoint.value,
    #     PFCPIEType.CreatedBridgeInfoforTSC.value,
    #     PFCPIEType.ATSSSControlParameters.value,
    #     PFCPIEType.RDSConfigurationInformation.value,
    #     PFCPIEType.PartialFailureInformationSessionEstablishmentResponse.value
    # ]
    res_list.append(IE_NodeId(ipv4=ie_dict(ies_dict, 60)['ipv4']))
    res_list.append(IE_Cause(cause=ie_dict(ies_dict, 19)['cause']))
    if ie_dict(ies_dict, 57):
        res_list.append(
            IE_FSEID(
                ipv4=ie_dict(ies_dict, 57)['ipv4'],
                v4=ie_dict(ies_dict, 57)['v4'],
                seid=ie_dict(ies_dict, 57)['seid']
            )
        )
    if ie_dict(ies_dict, 8):
        res_list.append(
            IE_CreatedPDR(
                IE_list=[
                    IE_PDR_Id(id=ie_dict(ies_dict, 8)['PDR_Id']),
                    IE_FTEID(
                        ipv4=ie_dict(ies_dict, 8)['PDR_ipv4'],
                        V4=ie_dict(ies_dict, 8)['PDR_V4'],
                        TEID=ie_dict(ies_dict, 8)['PDR_TEID']
                    )
                ]
            )
        )
    return res_list


def build_pfcp_session_modification_response(rsp_task):
    res_list = []
    if not rsp_task:
        return res_list
    ies_dict = rsp_task['IEs_dict']
    # mand = [
    #            PFCPIEType.Cause.value
    #        ],
    # opt = [
    #     PFCPIEType.OffendingIE.value,
    #     PFCPIEType.CreatedPDR.value,
    #     PFCPIEType.LoadControlInformation.value,
    #     PFCPIEType.OverloadControlInformation.value,
    #     PFCPIEType.UsageReportSessionModificationResponse.value,
    #     PFCPIEType.FailedRuleID.value,
    #     PFCPIEType.AdditionalUsageReportsInformation.value,
    #     PFCPIEType.CreatedTrafficEndpoint.value,
    #     PFCPIEType.TSCManagementInformationSessionModificationResponse.value,
    #     PFCPIEType.ATSSSControlParameters.value,
    #     PFCPIEType.UpdatedPDR.value,
    #     PFCPIEType.PacketRateStatusReport.value,
    #     PFCPIEType.PartialFailureInformationSessionModificationResponse.value
    # ]
    res_list.append(IE_Cause(cause=ie_dict(ies_dict, 19)['cause']))
    return res_list
