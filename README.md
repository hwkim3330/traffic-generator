# Traffic Generator - txgen & rxcap

고성능 패킷 생성 및 캡처 도구.

## 도구

| 도구 | 용도 | 핵심 기능 |
|------|------|----------|
| **txgen** | 패킷 생성 (TX) | sendmmsg 배치 전송, VLAN PCP, pcap 재생 |
| **rxcap** | 패킷 캡처 (RX) | recvmmsg 배치 수신, 지연 분석, pcap 저장 |

## 설치

```bash
make
sudo make install  # /usr/local/bin/
```

## 빠른 시작

```bash
# TX: UDP 전송
sudo ./txgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 100

# RX: 캡처
sudo ./rxcap eth1 --duration 60

# TX: 시퀀스 + 타임스탬프
sudo ./txgen eth0 -B IP -b MAC --seq --timestamp -r 500

# RX: 지연 측정 + pcap 저장
sudo ./rxcap eth1 --latency --pcap capture.pcap --duration 60

# pcap 재생
sudo ./txgen eth0 --replay capture.pcap
```

## txgen 주요 옵션

```
Usage: txgen [options] <interface>

Required:
  -B, --dst-ip IP          목적지 IP
  -b, --dst-mac MAC        목적지 MAC

Traffic:
  -r, --rate MBPS          속도 제한
  --duration SEC           전송 시간
  -Q, --vlan [PCP:]VLAN    VLAN 태그

Payload:
  --seq                    시퀀스 번호 (4 bytes)
  --timestamp              타임스탬프 (8 bytes)

Replay:
  --replay FILE            pcap 파일 재생
```

## rxcap 주요 옵션

```
Usage: rxcap [options] <interface>

Capture:
  --duration SEC           캡처 시간
  --pcap FILE              pcap 파일로 저장

Filter:
  --vlan VID               VLAN 필터
  --seq-only               시퀀스 헤더 있는 패킷만

Analysis:
  --seq                    시퀀스 추적
  --latency                지연 측정 (txgen --timestamp 필요)
```

## Payload 포맷 (12 bytes)

```
Bytes 0-3:  Sequence Number (network order)
Bytes 4-11: Timestamp (nanoseconds, host order)
```

## 의존성

- 없음 (표준 C/POSIX만 사용)
- libpcap 불필요

## 라이선스

GPLv2
