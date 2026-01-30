# trafgen - High-Performance Traffic Generator v1.2.0

Mausezahn(mz) 소스코드를 기반으로 개선한 고성능 트래픽 생성기.
TSN (Time-Sensitive Networking) 테스트에 최적화.

## 주요 기능

- **10+ Gbps** 처리량 (sendmmsg 배치 전송)
- **VLAN PCP/DEI** 지원 (802.1p 우선순위)
- **tc/qdisc 연동** (SO_PRIORITY)
- **DSCP/QoS** 마킹
- **멀티스레드** 아키텍처
- **토큰 버킷** 정밀 레이트 제한

## 개선사항 (vs mz)

| 기능 | mz | trafgen |
|------|-----|---------|
| 패킷 전송 | libnet_write() 단일 전송 | **sendmmsg() 배치 전송** |
| 멀티스레딩 | 제한적 | **완전한 멀티스레드** |
| 실시간 통계 | 종료 시 출력 | **1초 간격 실시간 출력** |
| Rate limiting | usleep 기반 | **토큰 버킷** |
| VLAN 우선순위 | PCP만 | **PCP + DEI** |
| tc 연동 | 없음 | **SO_PRIORITY** |
| 최대 처리량 | ~1 Gbps | **10+ Gbps** |

## 설치

```bash
# 빌드
make

# 시스템 설치 (선택)
sudo make install
```

## 사용법

### 기본 문법 (mz 호환)

```bash
sudo ./trafgen <interface> [options]
```

### 필수 옵션

| 옵션 | 설명 |
|------|------|
| `-B, --dst-ip IP` | 목적지 IP 주소 |
| `-b, --dst-mac MAC` | 목적지 MAC 주소 |

### 전체 옵션

```
Layer 2:
  -a, --src-mac MAC|rand   출발지 MAC (기본: 인터페이스 MAC)
  -b, --dst-mac MAC|rand   목적지 MAC
  -Q, --vlan [PCP[.DEI]:]VLAN  VLAN 태그 (다중 지정 가능)
                           PCP: Priority Code Point (0-7)
                           DEI: Drop Eligible Indicator (0-1)
                           예: 100, 5:100, 5.1:100

Layer 3:
  -A, --src-ip IP|rand     출발지 IP (기본: 인터페이스 IP)
  -B, --dst-ip IP          목적지 IP
  -D, --dscp VALUE         DSCP 값 (0-63)
  -T, --ttl VALUE          TTL 값 (기본: 64)

Layer 4:
  -t, --type TYPE          패킷 타입: udp, tcp, icmp, raw
  -p, --port PORT          목적지 포트 (기본: 5001)
  -P, --src-port PORT      출발지 포트

Traffic Control:
  -c, --count NUM          패킷 수 (0 = 무한)
  -r, --rate MBPS          목표 속도 (Mbps), 0 = 최대
  --duration SEC           지속 시간 (초)
  -w, --workers NUM        워커 스레드 수
  --skb-priority NUM       소켓 우선순위 (SO_PRIORITY)
                           tc/qdisc와 연동, pfifo_fast 밴드 매핑

Packet:
  -l, --length SIZE        패킷 크기 (기본: 1472)

Other:
  -q, --quiet              조용히 실행
  -v, --verbose            상세 출력
  -S, --simulation         시뮬레이션 (전송 안함)
```

## 예제

### 기본 트래픽 (최대 속도)

```bash
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55
```

### 속도 제한

```bash
# 1 Gbps
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 1000

# 500 Mbps, 60초
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 500 --duration 60
```

### 패킷 크기 조절

```bash
# 작은 패킷 (높은 pps)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -l 64

# 점보 프레임
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -l 9000
```

### VLAN 태깅

```bash
# 단일 VLAN
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 100

# PCP (Priority Code Point) + VLAN
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 5:100

# PCP + DEI (Drop Eligible Indicator) + VLAN
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 6.1:100

# QinQ (이중 VLAN)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 100 -Q 200
```

### tc/qdisc 연동

```bash
# tc qdisc 설정 (prio 또는 mqprio)
sudo tc qdisc add dev eth0 root handle 1: prio bands 8

# SKB 우선순위에 따른 트래픽 분류
# Band 0 (높은 우선순위)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --skb-priority 0

# Band 1 (중간 우선순위)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --skb-priority 1

# VLAN PCP와 SKB Priority 동시 사용 (TSN 테스트)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 6:100 --skb-priority 6
```

### QoS (DSCP)

```bash
# DSCP EF (46) - VoIP
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -D 46

# DSCP AF41 (34) - Video
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -D 34
```

### TCP SYN

```bash
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -t tcp -p 80
```

### 멀티 워커 (높은 처리량)

```bash
# 8 워커 스레드
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -w 8
```

## 출력 예시

```
Configuration:
  Interface:    enp11s0 (00:e0:4c:68:12:d1)
  Destination:  192.168.1.100 (00:11:22:33:44:55)
  Source IP:    192.168.1.1
  Ports:        49383 -> 5001
  Packet Size:  1472 bytes
  Rate:         1000 Mbps
  Duration:     10 seconds
  Workers:      8, Batch: 512
  VLAN 1:       100 (PCP: 6, DEI: 0)
  SKB Priority: 6

════════════════════════════════════════════════════════════════════════════════
 trafgen v1.2.0 - High-Performance Traffic Generator
 8 workers, 1472 byte packets, batch 512, rate: 1000 Mbps
════════════════════════════════════════════════════════════════════════════════
     Time │        Packets │   Rate (pps) │      Throughput │     Errors
──────────┼────────────────┼──────────────┼─────────────────┼────────────
    1.0s │          84480 │        84480 │      994.9 Mbps │          0
    2.0s │         168960 │        84480 │      994.9 Mbps │          0
    3.0s │         253440 │        84480 │      994.9 Mbps │          0
──────────┴────────────────┴──────────────┴─────────────────┴────────────

Summary:
  Duration:       3.00 seconds
  Total Packets:  253,440
  Total Data:     0.347 GB
  Avg Rate:       84,480 pps
  Avg Throughput: 0.995 Gbps
  Errors:         0
════════════════════════════════════════════════════════════════════════════════
```

## TSN 테스트

### CBS (Credit-Based Shaper)

```bash
# PCP 0-3 → TC6 (Priority 6), PCP 4-7 → TC2 (Priority 2)

# TC2 트래픽 (PCP 4, Priority 2) - 1.5 Mbps
sudo ./trafgen enp11s0 -B 192.168.1.100 -b 00:11:22:33:44:55 \
    -Q 4:100 --skb-priority 2 -r 1500

# TC6 트래픽 (PCP 0, Priority 6) - 3.5 Mbps
sudo ./trafgen enp11s0 -B 192.168.1.100 -b 00:11:22:33:44:55 \
    -Q 0:100 --skb-priority 6 -r 3500
```

### TAS (Time-Aware Shaper)

```bash
# 8개 Traffic Class 동시 테스트
for prio in 0 1 2 3 4 5 6 7; do
    sudo ./trafgen enp11s0 -B 192.168.1.100 -b 00:11:22:33:44:55 \
        -Q $prio:100 --skb-priority $prio -r 100 &
done
```

### mqprio qdisc 설정

```bash
# 8-queue TSN 설정 (Intel i210 등)
sudo tc qdisc replace dev enp11s0 parent root handle 100 mqprio \
    num_tc 8 \
    map 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 \
    queues 1@0 1@1 1@2 1@3 1@4 1@5 1@6 1@7 \
    hw 0

# TC별 트래픽 생성
sudo ./trafgen enp11s0 -B 192.168.1.100 -b MAC -Q 7:100 --skb-priority 7
```

## 성능 튜닝

```bash
# 소켓 버퍼 증가
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864

# NIC 링버퍼
sudo ethtool -G eth0 tx 4096
```

## 파일 구조

```
traffic-generator/
├── src/
│   └── trafgen.c      # 메인 소스 코드
├── mz-src/            # 원본 mz 소스 (참고용)
├── Makefile
└── README.md
```

## 라이선스

GPLv2 (원본 Mausezahn 라이선스 준수)

## 참고

- [Mausezahn (mz)](https://github.com/uweber/mausezahn) - 원본 트래픽 생성기
- [netsniff-ng](http://netsniff-ng.org/) - mz 포함 툴킷
- [sendmmsg(2)](https://man7.org/linux/man-pages/man2/sendmmsg.2.html) - 배치 전송 시스템콜
