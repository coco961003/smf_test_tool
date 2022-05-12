from binascii import unhexlify

import NGAP_DEC
from utils import ipv4_2_val, trans_int_to_byte

# PDU 建立
setup_rsp_val = {
    'qosFlowPerTNLInformation': {
        'uPTransportLayerInformation': (
            'gTPTunnel',
            {
                'transportLayerAddress': ipv4_2_val('172.18.8.1'),
                'gTP-TEID': trans_int_to_byte(1)
            }
        ),
        'associatedQosFlowList': [
            {
                'qosFlowIdentifier': 5
            }
        ]
    }
}

pdu_rel_rsp_val = {}

path_switch_val = {
    'dL-NGU-UP-TNLInformation': (
        'gTPTunnel',
        {
            'transportLayerAddress': ipv4_2_val('172.18.8.1'),
            'gTP-TEID': trans_int_to_byte(1)
        }
    ),
    'userPlaneSecurityInformation': {
        'securityResult': {
            'integrityProtectionResult': 'performed',
            'confidentialityProtectionResult': 'performed'
        },
        'securityIndication': {
            'integrityProtectionIndication': 'required',
            'confidentialityProtectionIndication': 'required'
        }
    }
    , 'qosFlowAcceptedList': [
        {
            'qosFlowIdentifier': 5
        }
    ]
}


def build_setup_resp_from_decode():
    encode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupResponseTransfer

    '''
       [(['qosFlowPerTNLInformation', 'uPTransportLayerInformation', 'gTPTunnel', 'transportLayerAddress'], (2886862849, 32)), (['qosFlowPerTNLInformation', 'uPTransportLayerInformation', 'gTPTunnel', 'gTP-TEID'], b'\x00\x00\x00\x01'), (['qosFlowPerTNLInformation', 'associatedQosFlowList', 0, 'qosFlowIdentifier'], 5)] 
    '''
    encode_obj.from_aper(
        unhexlify('0003e0ac120801000000010005')
    )

    encode_obj.set_val_at(
        ['qosFlowPerTNLInformation', 'uPTransportLayerInformation', 'gTPTunnel', 'transportLayerAddress'],
        ipv4_2_val('172.18.8.1')
    )
    encode_obj.set_val_at(
        ['qosFlowPerTNLInformation', 'uPTransportLayerInformation', 'gTPTunnel', 'gTP-TEID'],
        b'\x00\x00\x00\x01'
    )
    encode_obj.set_val_at(
        ['qosFlowPerTNLInformation', 'associatedQosFlowList', 0, 'qosFlowIdentifier'],
        5
    )

    return encode_obj.to_aper()


def build_setup_resp_from_encode():
    encode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupResponseTransfer

    encode_obj.set_val(setup_rsp_val)

    return encode_obj
    # return encode_obj.to_aper()


def build_pdu_rel_rsp_from_decode():
    encode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceReleaseResponseTransfer

    encode_obj.from_aper(
        unhexlify('00')
    )

    return encode_obj.to_aper()


def build_pdu_rel_rsp_from_encode():
    encode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceReleaseResponseTransfer
    encode_obj.set_val(pdu_rel_rsp_val)
    return encode_obj
    # return encode_obj.to_aper()


def build_xn_switch_req_from_encode():
    encode_obj = NGAP_DEC.NGAP_IEs.PathSwitchRequestTransfer
    encode_obj.set_val(path_switch_val)
    return encode_obj
    # return encode_obj.to_aper()


def build_handover_required_from_encode():
    val = {
        'directForwardingPathAvailability': 'direct-path-available'
    }
    encode_obj = NGAP_DEC.NGAP_IEs.HandoverRequiredTransfer
    encode_obj.set_val(val)
    return encode_obj


def build_handover_req_ack_trans_from_encode():
    val = {
        'dL-NGU-UP-TNLInformation': (
            'gTPTunnel', {
                'transportLayerAddress': ipv4_2_val('172.18.8.1'),
                'gTP-TEID': b'\x00\x00\x00\x01'
            }
        ),
        'dLForwardingUP-TNLInformation': (
            'gTPTunnel', {
                'transportLayerAddress': ipv4_2_val('172.18.8.1'),
                'gTP-TEID': b'\x00\x00\x00\x02'
            }
        ),
        'qosFlowSetupResponseList': [
            {
                'qosFlowIdentifier': 5,
                'dataForwardingAccepted': 'data-forwarding-accepted'
            }
        ],
        'dataForwardingResponseDRBList': [
            {
                'dRB-ID': 5,
                'dLForwardingUP-TNLInformation': (
                    'gTPTunnel', {
                        'transportLayerAddress': ipv4_2_val('172.18.8.1'),
                        'gTP-TEID': b'\x00\x00\x00\x02'
                    }
                )
            }
        ]
    }
    encode_obj = NGAP_DEC.NGAP_IEs.HandoverRequestAcknowledgeTransfer
    encode_obj.set_val(val)
    return encode_obj


def build_pdu_resource_setup_failure_trans():
    encode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupUnsuccessfulTransfer
    val = {
        'cause': (
            'protocol',
            'transfer-syntax-error'
        )
    }
    encode_obj.set_val(val)
    return encode_obj
