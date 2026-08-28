from __future__ import annotations
from .ingress_models import ClassifiedResult,ExpectedAction,Observation,SegmentationResult

def classify(expected:ExpectedAction,sender:Observation,receiver:Observation|None)->ClassifiedResult:
    if receiver is None or not receiver.observer_healthy or receiver.capture_overflow or not receiver.interface_matches:
        return ClassifiedResult(SegmentationResult.INDETERMINATE,"low",("Destination observer evidence was unavailable or unhealthy.",),"medium")
    reached=receiver.observed is True or sender.response in {"tcp_rst","icmp_port_unreachable","responder_ack","connected"}
    if expected is ExpectedAction.DENY:
        if reached:return ClassifiedResult(SegmentationResult.FAIL_UNEXPECTED_ALLOW,"high",("Destination evidence proves the path crossed the boundary.","A closed service is not segmentation."),"high")
        if receiver.observed is False and sender.attempts>=2:return ClassifiedResult(SegmentationResult.PASS_EXPECTED_DENY,"high",("Healthy observer saw no approved attempts.",),"informational")
    else:
        if sender.response=="responder_ack":return ClassifiedResult(SegmentationResult.PASS_EXPECTED_ALLOW,"high",("Signed responder acknowledgement proved application reachability.",),"informational")
        if sender.response=="tcp_rst":return ClassifiedResult(SegmentationResult.NETWORK_REACHABLE_SERVICE_CLOSED,"high",("Destination-generated TCP RST proves network reachability; service was closed.",),"informational")
        if sender.response=="icmp_port_unreachable":return ClassifiedResult(SegmentationResult.NETWORK_REACHABLE_SERVICE_REJECTED,"high",("Destination ICMP rejection proves network reachability.",),"informational")
        if receiver.observed is True:return ClassifiedResult(SegmentationResult.PASS_EXPECTED_ALLOW,"high",("Destination observer recorded the intended packet.",),"informational")
        if receiver.observed is False and sender.attempts>=2:return ClassifiedResult(SegmentationResult.FAIL_UNEXPECTED_DENY,"high",("Healthy observer did not see the expected allowed flow.",),"medium")
    return ClassifiedResult(SegmentationResult.INDETERMINATE,"low",("Insufficient attempts or evidence.",),"medium")
