# Traffic Generator - txgen & rxcap

고성능 패킷 생성 및 캡처 도구. 네트워크 성능 측정, QoS 테스트, 트래픽 분석용.

## 특징

- **의존성 없음**: 표준 C/POSIX만 사용 (libpcap 불필요)
- **고성능**: sendmmsg/recvmmsg 배치 처리, lock-free token bucket rate limiting
- **정밀 측정**: per-packet timestamp, atomic 통계, CAS 기반 min/max
- **프로토콜 지원**: IPv4/IPv6 UDP, VLAN (802.1Q, QinQ, 802.1ad)
- **Cleanup-safe**: 모든 에러 경로에서 리소스 누수 없음

## 도구

| 도구 | 용도 | 핵심 기능 |
|------|------|----------|
| **txgen** | 패킷 생성 (TX) | sendmmsg 배치 전송, Multi-TC, VLAN PCP, pcap 재생 |
| **rxcap** | 패킷 캡처 (RX) | recvmmsg 배치 수신, 지연/IAT 분석, pcap 저장 |

## 요구사항

- Linux (AF_PACKET, sendmmsg/recvmmsg 지원)
- GCC with C11 support
- Root 권한 (raw socket 사용)

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
sudo ./txgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --seq --timestamp -r 500 &
sudo ./rxcap eth1 --seq --latency --duration 30

# VLAN + PCP 태깅 (PCP 5, VLAN 100)
sudo ./txgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 5:100 -r 1000

# Multi-TC 모드 (PCP 0-7 동시 전송)
sudo ./txgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --multi-tc 0-7:100 --seq --timestamp

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
  -a, --src-mac MAC|rand     소스 MAC (기본: 인터페이스 MAC)
  -Q, --vlan [PCP[.DEI]:]VID VLAN 태그 (예: 100, 5:100, 5.1:100)

Layer 3:
  -A, --src-ip IP|rand|RANGE 소스 IP (기본: 인터페이스 IP)
  -D, --dscp VALUE           DSCP (0-63)
  -T, --ttl VALUE            TTL (기본: 64)

Layer 4:
  -t, --type TYPE            udp, tcp, icmp, raw (기본: udp)
  -p, --port PORT|RANGE      목적지 포트 (기본: 9999)
  -P, --src-port PORT|RANGE  소스 포트

Traffic Control:
  -c, --count NUM            패킷 수 (0=무한)
  -r, --rate MBPS            속도 제한 (Mbps)
  --pps NUM                  속도 제한 (pps)
  --duration SEC             전송 시간
  -w, --workers NUM          워커 스레드 수 (기본: 1)
  --batch NUM                배치 크기 (기본: 512)

Payload:
  --seq                      시퀀스 번호 삽입 (4 bytes)
  --timestamp                타임스탬프 삽입 (8 bytes)
  -s, --size SIZE            패킷 크기 (기본: 64)

Multi-TC:
  --multi-tc TC_SPEC[:VLAN]  여러 TC 동시 전송 (예: 0-7:100)

Replay:
  --replay FILE              pcap 파일 재생

Performance:
  --affinity                 CPU 고정 (워커별 자동 분배)
```

## rxcap 옵션

```
Usage: rxcap [options] <interface>

Capture:
  --duration SEC             캡처 시간 (0=무한)
  --pcap FILE                pcap 저장 (Wireshark 호환)
  --batch NUM                배치 크기 (기본: 256)

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
  -v, --verbose              상세 출력

Performance:
  --affinity[=CPU]           CPU 고정 (기본: CPU 0)
```

## Payload 포맷

txgen `--seq --timestamp` 옵션 사용 시 UDP payload 앞 12바이트:

```
Offset  Size  Field
------  ----  -----
0       4     Sequence Number (network byte order)
4       8     Timestamp in nanoseconds (network byte order)
```

rxcap `--seq --latency` 옵션으로 분석.

## 지연 측정

### 주의사항

- **같은 머신에서만 정확**: CLOCK_MONOTONIC_RAW 사용
- 크로스 머신 측정은 PTP 동기화된 HW 타임스탬프 필요
- `kernel_drops > 0`이면 지연 값 신뢰 불가 (수신측 병목)

### 측정 예시

```bash
# Terminal 1 (RX)
sudo ./rxcap eth1 --seq --latency --pcp-stats --duration 30

# Terminal 2 (TX)
sudo ./txgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 \
    --seq --timestamp -r 1000 --duration 30
```

## 프로토콜 지원

| 프로토콜 | txgen | rxcap |
|----------|:-----:|:-----:|
| IPv4 UDP | ✓ | ✓ |
| IPv6 UDP | - | ✓ (no ext headers) |
| VLAN 802.1Q (0x8100) | ✓ | ✓ |
| QinQ (0x88a8) | ✓ | ✓ |
| 802.1ad (0x9100) | ✓ | ✓ |

## 기술 구현

### txgen
- `sendmmsg()` 배치 전송 (기본 512 패킷/syscall)
- Lock-free token bucket rate limiting (per-worker, no contention)
- Multi-TC 모드: `fork()`로 TC별 프로세스 분리
- Cleanup-safe 스레드 (goto cleanup 패턴)

### rxcap
- `recvmmsg()` 배치 수신 (기본 256 패킷/syscall)
- Per-packet timestamp (정확한 IAT/latency 측정)
- Atomic 통계 + CAS min/max (thread-safe)
- Batch PCAP write (단일 lock으로 I/O 최소화)
- `SO_RXQ_OVFL` 커널 드롭 감지
- Cleanup-safe 스레드 (goto cleanup 패턴)

## 성능 튜닝

```bash
# 수신 버퍼 증가 (드롭 감소)
sudo sysctl -w net.core.rmem_max=67108864
sudo sysctl -w net.core.rmem_default=67108864

# 송신 버퍼 증가
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864

# CPU 고정 (jitter 감소)
sudo ./txgen eth0 ... --affinity
sudo ./rxcap eth1 ... --affinity=2

# 멀티 워커로 처리량 증가
sudo ./txgen eth0 ... -w 4 --affinity
```

### 주의사항

- PCAP 저장 시 5Gbps 이상에서 디스크 I/O 병목 가능
- 높은 pps에서는 `--batch` 값 증가 고려
- `kernel_drops`가 증가하면 수신 버퍼 증가 또는 CPU affinity 설정

## CSV 출력 스키마

rxcap `--csv` 옵션 사용 시:

```
time_s,total_pkts,total_pps,total_mbps,drops,
pcp0_pkts,pcp1_pkts,...,pcp7_pkts,
latency_min_ns,latency_avg_ns,latency_max_ns,
iat_min_ns,iat_avg_ns,iat_max_ns
```

## 라이선스

Copyright (C) 2025 KETI (Korea Electronics Technology Institute)

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License version 2 as published by the
Free Software Foundation.
