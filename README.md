# trafgen - High-Performance Traffic Generator v1.4.0

Mausezahn(mz) 소스코드를 기반으로 개선한 고성능 트래픽 생성기.
TSN (Time-Sensitive Networking) 테스트에 최적화.

## 주요 기능

- **10+ Gbps** 처리량 (sendmmsg 배치 전송)
- **VLAN PCP/DEI** 지원 (802.1p 우선순위)
- **Multi-TC 모드** - 8개 TC 동시 전송
- **RX 통계** - 손실률 실시간 측정
- **tc/qdisc 연동** (SO_PRIORITY, PACKET_FANOUT)
- **CPU Affinity** - 코어 고정
- **DSCP/QoS** 마킹
- **토큰 버킷** 정밀 레이트 제한
- **패킷간 딜레이** (ns/us/ms 정밀도)

## 개선사항 (vs mz)

| 기능 | mz | trafgen |
|------|-----|---------|
| 패킷 전송 | libnet_write() 단일 전송 | **sendmmsg() 배치 전송** |
| 멀티스레딩 | 제한적 | **완전한 멀티스레드** |
| 실시간 통계 | 종료 시 출력 | **1초 간격 실시간 출력** |
| Rate limiting | usleep 기반 | **토큰 버킷** |
| VLAN 우선순위 | PCP만 | **PCP + DEI** |
| tc 연동 | 없음 | **SO_PRIORITY + FANOUT** |
| Multi-TC | 없음 | **8개 TC 동시 전송** |
| RX 통계 | 없음 | **손실률 측정** |
| CPU 최적화 | 없음 | **Affinity 지원** |
| 최대 처리량 | ~1 Gbps | **10+ Gbps** |

## 설치

```bash
# 빌드
make

# 시스템 설치 (선택)
sudo make install
```

## 빠른 시작

```bash
# 기본 UDP 트래픽 (최대 속도)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55

# 1 Gbps, 10초
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 1000 --duration 10

# 8개 TC 동시 전송 (TSN 테스트)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --multi-tc 0-7:100

# TX/RX 손실률 측정
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -R
```

## 전체 옵션

```
Usage: trafgen [options] <interface>

Required:
  <interface>              네트워크 인터페이스
  -B, --dst-ip IP          목적지 IP 주소
  -b, --dst-mac MAC        목적지 MAC 주소

Layer 2:
  -a, --src-mac MAC|rand   출발지 MAC
  -Q, --vlan [PCP[.DEI]:]VLAN  VLAN 태그 (다중 지정 가능)
                           예: 100, 5:100, 5.1:100

Layer 3:
  -A, --src-ip IP|rand|IP-IP  출발지 IP (단일/랜덤/범위)
  -D, --dscp VALUE         DSCP 0-63
  -T, --ttl VALUE          TTL (기본: 64)
  --df                     Don't Fragment 플래그

Layer 4:
  -t, --type TYPE          udp, tcp, icmp, raw (기본: udp)
  -p, --port PORT|PORT-PORT  목적지 포트 (단일/범위)
  -P, --src-port PORT      출발지 포트
  --tcp-flags FLAGS        TCP 플래그: S=SYN,A=ACK,F=FIN,R=RST,P=PSH,U=URG

Traffic Control:
  -c, --count NUM          패킷 수 (0=무한)
  -r, --rate MBPS          속도 제한 (Mbps)
  --pps NUM                속도 제한 (pps)
  --duration SEC           지속 시간 (초)
  -w, --workers NUM        워커 스레드 수 (기본: CPU 수)
  --batch NUM              배치 크기 (기본: 512)
  -d, --delay DELAY        패킷간 딜레이 (100ns, 10us, 1ms)
  --delay-per-pkt          패킷당 딜레이 적용 (기본: 배치당)
  --skb-priority NUM       소켓 우선순위 (tc/qdisc 연동)
  --multi-tc TC[:VLAN]     멀티 TC 모드 (예: 0-7:100)

Performance:
  --fanout[=MODE]          PACKET_FANOUT (hash,lb,cpu,rnd)
  --affinity               워커 스레드 CPU 코어 고정

RX Statistics:
  -R, --rx[=IFACE]         RX 통계 활성화 (손실률 측정)

Packet:
  -l, --length SIZE|MIN-MAX  패킷 크기 (고정/랜덤 범위)
  --payload-type TYPE      zero, random, increment, pattern, ascii
  --seq                    시퀀스 번호 삽입
  --timestamp              타임스탬프 삽입

Checksum:
  --ip-csum                IP 체크섬 계산
  --l4-csum                TCP/UDP 체크섬 계산

Output:
  --stats-file FILE        통계 CSV 파일 출력
  -q, --quiet              조용히 실행
  -v, --verbose            상세 출력
```

## 예제

### 기본 트래픽

```bash
# 최대 속도
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55

# 속도 제한
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 1000 --duration 60

# 작은 패킷 (높은 PPS)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -l 64
```

### VLAN 태깅

```bash
# VLAN 100
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 100

# PCP 6, VLAN 100
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 6:100

# PCP 6, DEI 1, VLAN 100
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 6.1:100

# QinQ (이중 VLAN)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 100 -Q 200
```

### Multi-TC 모드 (TSN)

```bash
# 8개 TC 동시 전송 (VLAN 100)
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --multi-tc 0-7:100 -r 100

# 특정 TC만 (0, 2, 4, 6)
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --multi-tc 0,2,4,6:100

# CBS 테스트용 (TC2, TC6)
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --multi-tc 2,6:100 -r 500
```

### RX 통계 (손실률 측정)

```bash
# 같은 인터페이스에서 TX/RX 측정
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -R

# 다른 인터페이스에서 RX (루프백 테스트)
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -R eth1

# 시퀀스 번호로 패킷 손실 추적
sudo ./trafgen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -R --seq
```

### 패킷간 딜레이

```bash
# 1ms 딜레이 (패킷당) → ~1000 pps
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC -d 1ms --delay-per-pkt

# 100us 딜레이 (배치당)
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC -d 100us
```

### tc/qdisc 연동

```bash
# tc qdisc 설정
sudo tc qdisc add dev eth0 root handle 1: prio bands 8

# SKB 우선순위로 트래픽 분류
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --skb-priority 6

# VLAN PCP + SKB Priority (TSN)
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC -Q 6:100 --skb-priority 6
```

### 성능 최적화

```bash
# CPU 코어 고정
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --affinity

# PACKET_FANOUT (멀티큐 NIC)
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --fanout=cpu

# 둘 다 사용
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --affinity --fanout=cpu
```

## 출력 예시

### 기본 모드

```
════════════════════════════════════════════════════════════════════════════════
 trafgen v1.4.0 - High-Performance Traffic Generator
 16 workers, 1472 byte packets, batch 512, rate: 1000 Mbps
════════════════════════════════════════════════════════════════════════════════
     Time │        Packets │   Rate (pps) │      Throughput │     Errors
──────────┼────────────────┼──────────────┼─────────────────┼────────────
    1.0s │          84480 │        84480 │      994.9 Mbps │          0
    2.0s │         168960 │        84480 │      994.9 Mbps │          0
    3.0s │         253440 │        84480 │      994.9 Mbps │          0
──────────┴────────────────┴──────────────┴─────────────────┴────────────

Summary:
  Duration:       3.00 seconds
  TX Packets:     253440
  TX Throughput:  0.995 Gbps
  TX Errors:      0
════════════════════════════════════════════════════════════════════════════════
```

### RX 모드 (손실률 측정)

```
════════════════════════════════════════════════════════════════════════════════
 trafgen v1.4.0 - High-Performance Traffic Generator
 16 workers, 1472 byte packets, batch 512, rate: 100 Mbps | RX: eth1
════════════════════════════════════════════════════════════════════════════════
     Time │      TX Pkts │     TX pps │      TX Mbps │      RX Pkts │     RX pps │     Loss
──────────┼──────────────┼────────────┼──────────────┼──────────────┼────────────┼──────────
     1.0s │        64512 │      64506 │        759.6 │        64259 │      64253 │    0.39%
     2.0s │       138240 │      73722 │        868.2 │       136772 │      72507 │    1.06%
     3.0s │       211968 │      73723 │        868.2 │       209691 │      72914 │    1.07%
──────────┴──────────────┴────────────┴──────────────┴──────────────┴────────────┴──────────

Summary:
  TX Packets:     211968
  TX Throughput:  0.868 Gbps
  ────────────────────────
  RX Packets:     209691
  RX Throughput:  0.858 Gbps
  Packet Loss:    1.07%
════════════════════════════════════════════════════════════════════════════════
```

### Multi-TC 모드

```
══════════════════════════════════════════════════════════════════════════════
 Multi-TC Mode: 8 Traffic Classes (PCP 0-7)
 VLAN: 100 | Rate: 100 Mbps/TC | Duration: 10 sec
══════════════════════════════════════════════════════════════════════════════

All 8 TCs completed.
```

## TSN 테스트

### CBS (Credit-Based Shaper)

```bash
# TC2, TC6 동시 테스트
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --multi-tc 2,6:100 -r 500

# 또는 개별 실행
sudo ./trafgen eth0 -B IP -b MAC -Q 2:100 --skb-priority 2 -r 1500 &
sudo ./trafgen eth0 -B IP -b MAC -Q 6:100 --skb-priority 6 -r 3500 &
```

### TAS (Time-Aware Shaper)

```bash
# 8개 TC 모두 테스트
sudo ./trafgen eth0 -B 192.168.1.100 -b MAC --multi-tc 0-7:100 -r 100 --duration 60
```

### mqprio qdisc 설정

```bash
# 8-queue TSN 설정 (Intel i210 등)
sudo tc qdisc replace dev eth0 parent root handle 100 mqprio \
    num_tc 8 \
    map 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 \
    queues 1@0 1@1 1@2 1@3 1@4 1@5 1@6 1@7 \
    hw 0

# TC별 트래픽 생성
sudo ./trafgen eth0 -B IP -b MAC --multi-tc 0-7:100 --skb-priority 7
```

## 성능 튜닝

```bash
# 소켓 버퍼 증가
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864
sudo sysctl -w net.core.rmem_max=67108864

# NIC 링버퍼
sudo ethtool -G eth0 tx 4096 rx 4096

# CPU 거버너 (최대 성능)
sudo cpupower frequency-set -g performance
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

## 버전 히스토리

- **v1.4.0**: PACKET_FANOUT, CPU Affinity, RX 통계 (손실률 측정)
- **v1.3.0**: Multi-TC 모드 (8개 TC 동시 전송)
- **v1.2.1**: 패킷간 딜레이 (ns/us/ms 정밀도)
- **v1.2.0**: tc/qdisc 연동 (SO_PRIORITY), VLAN DEI 지원
- **v1.1.0**: 토큰 버킷, IP/포트 범위, TCP 플래그, 시퀀스/타임스탬프
- **v1.0.0**: 초기 버전 (sendmmsg, 멀티스레드, VLAN PCP)

## 라이선스

GPLv2 (원본 Mausezahn 라이선스 준수)

## 참고

- [Mausezahn (mz)](https://github.com/uweber/mausezahn) - 원본 트래픽 생성기
- [netsniff-ng](http://netsniff-ng.org/) - mz 포함 툴킷
- [sendmmsg(2)](https://man7.org/linux/man-pages/man2/sendmmsg.2.html) - 배치 전송 시스템콜
- [PACKET_FANOUT](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt) - 멀티큐 분산
