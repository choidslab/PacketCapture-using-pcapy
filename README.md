### Python pcapy를 이용한 네트워크 패킷 자동 수집 스크립트(This program is an automatic packet collection script using python pcapy & dpkt module.)

1. 네트워크 패킷 분석을 위해 구현한 패킷 자동 수집 스크립트입니다. 
2. `open_live()` 함수를 이용하여 NIC 지정을 할 수 있으며 `setfilter()` 함수에 BPF 필터 문법을 지정하여 원하는 프로토콜 패킷을 수집할 수 있습니다. 
3. pcapy 모듈과 같이 패킷 자동 수집 기능을 제공하는 `scapy` 모듈의 경우 패킷 자동 수집 시, CPU Overhead가 심하여 사용하지 않았습니다.(Scapy 모듈은 패킷 수집보다는 분석에 더 많이 활용되는 것 같습니다.)