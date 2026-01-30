# Traffic Generator - txgen & rxcap

고성능 패킷 생성 및 캡처 도구. 네트워크 성능 측정, TSN 실험, 트래픽 분석용.

## 특징

- **의존성 없음**: 표준 C/POSIX만 사용 (libpcap 불필요)
- **고성능**: sendmmsg/recvmmsg 배치 처리, lock-free rate limiting
- **정밀 측정**: per-packet timestamp, atomic 통계, CAS 기반 min/max
- **프로토콜 지원**: IPv4/IPv6 UDP, VLAN (802.1Q, QinQ, 802.1ad)

## 도구

| 도구 | 용도 | 핵심 기능 |
|------|------|----------|
| **txgen** | 패킷 생성 (TX) | sendmmsg 배치 전송, Multi-TC, VLAN PCP, pcap 재생 |
| **rxcap** | 패킷 캡처 (RX) | recvmmsg 배치 수신, 지연/IAT 분석, pcap 저장 |

## 설치

```bash
make
sudo make install  # /usr/local/bin/
```

## 빠른 시작

```bash
# 기본 UDP 전송 (100 Mbps)
sudo ./txgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 100

# 기본 캡처 (60초)
sudo ./rxcap eth1 --duration 60

# 지연 측정 (TX + RX 동시 실행, 같은 머신에서)
sudo ./txgen eth0 -B IP -b MAC --seq --timestamp -r 500 &
sudo ./rxcap eth1 --seq --latency --duration 30

# VLAN + PCP 태깅 (PCP 5, VLAN 100)
sudo ./txgen eth0 -B IP -b MAC -Q 5:100 -r 1000

# Multi-TC 모드 (PCP 0-7 동시 전송)
sudo ./txgen eth0 -B IP -b MAC --multi-tc 0-7:100 --seq --timestamp

# pcap 캡처 및 재생
sudo ./rxcap eth1 --pcap capture.pcap --duration 10
sudo ./txgen eth0 --replay capture.pcap -r 100
```

## txgen 옵션

```
Usage: txgen [options] <interface>

Required:
  -B, --dst-ip IP            목적지 IP
  -b, --dst-mac MAC          목적지 MAC

Layer 2:
  -a, --src-mac MAC|rand     소스 MAC
  -Q, --vlan [PCP[.DEI]:]VID VLAN 태그 (예: 100, 5:100, 5.1:100)

Layer 3:
  -A, --src-ip IP|rand|RANGE 소스 IP
  -D, --dscp VALUE           DSCP (0-63)
  -T, --ttl VALUE            TTL (기본: 64)

Layer 4:
  -t, --type TYPE            udp, tcp, icmp, raw (기본: udp)
  -p, --port PORT|RANGE      목적지 포트
  -P, --src-port PORT|RANGE  소스 포트

Traffic Control:
  -c, --count NUM            패킷 수 (0=무한)
  -r, --rate MBPS            속도 제한 (Mbps)
  --pps NUM                  속도 제한 (pps)
  --duration SEC             전송 시간
  -w, --workers NUM          워커 스레드 수
  --batch NUM                배치 크기 (기본: 512)

Payload:
  --seq                      시퀀스 번호 삽입 (4 bytes)
  --timestamp                타임스탬프 삽입 (8 bytes)
  -s, --size SIZE            패킷 크기

Multi-TC:
  --multi-tc TC_SPEC[:VLAN]  여러 TC 동시 전송 (예: 0-7:100)

Replay:
  --replay FILE              pcap 파일 재생
```

## rxcap 옵션

```
Usage: rxcap [options] <interface>

Capture:
  --duration SEC             캡처 시간
  --pcap FILE                pcap 저장 (Wireshark 호환)
  --batch NUM                배치 크기 (기본: 64)

Filter:
  --vlan VID                 VLAN ID 필터
  --pcp PCP                  PCP 필터
  --seq-only                 시퀀스 헤더 있는 패킷만

Analysis:
  --seq                      시퀀스 추적 (loss/dup/reorder)
  --latency                  지연 측정 (txgen --timestamp 필요)
  --pcp-stats                PCP별 통계

Output:
  --csv FILE                 CSV 출력
  -q, --quiet                조용한 모드

Performance:
  --affinity[=CPU]           CPU 고정
```

## Payload 포맷 (12 bytes)

```
Offset  Size  Description
------  ----  -----------
0       4     Sequence Number (network byte order, big-endian)
4       8     Timestamp in nanoseconds (network byte order)
```

txgen `--seq --timestamp` 옵션으로 생성, rxcap `--seq --latency`로 분석.

## 지연 측정 주의사항

- **같은 머신에서만 정확**: CLOCK_MONOTONIC_RAW 사용
- 크로스 머신 지연은 PTP 동기화된 HW 타임스탬프 필요
- `kernel_drops > 0`이면 지연 값 신뢰 불가

## 프로토콜 지원

| 프로토콜 | txgen | rxcap |
|----------|-------|-------|
| IPv4 UDP | ✅ | ✅ |
| IPv6 UDP | ❌ | ✅ (no ext headers) |
| VLAN 802.1Q (0x8100) | ✅ | ✅ |
| QinQ (0x88a8) | ✅ | ✅ |
| 802.1ad (0x9100) | ✅ | ✅ |

## 기술 구현

### txgen
- `sendmmsg()` 배치 전송 (512 패킷/syscall)
- Lock-free token bucket rate limiting (per-worker)
- Multi-TC 모드: fork()로 TC별 프로세스 분리

### rxcap
- `recvmmsg()` 배치 수신 (64 패킷/syscall)
- Per-packet timestamp (정확한 IAT/latency)
- Atomic 통계 + CAS min/max (thread-safe)
- Batch PCAP write (lock 최소화)
- SO_RXQ_OVFL 커널 드롭 감지

## 성능 팁

```bash
# 수신 버퍼 증가
sudo sysctl -w net.core.rmem_max=67108864
sudo sysctl -w net.core.rmem_default=67108864

# CPU 고정 (jitter 감소)
sudo ./txgen eth0 ... --affinity
sudo ./rxcap eth1 ... --affinity=2

# PCAP 저장 시 드롭 주의 (5Gbps 이상에서 병목 가능)
```

## 라이선스

GPLv2
