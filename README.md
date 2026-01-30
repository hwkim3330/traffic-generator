# TSN Traffic Tools - tsngen & tsnrecv

고성능 TSN (Time-Sensitive Networking) 트래픽 생성 및 분석 도구.

## 도구 구성

| 도구 | 용도 | 핵심 기능 |
|------|------|----------|
| **tsngen** | 트래픽 생성 (TX) | sendmmsg 배치 전송, Multi-TC, VLAN PCP |
| **tsnrecv** | 트래픽 수신 (RX) | recvmmsg 배치 수신, PCP별 통계, 지연 분석 |

## 주요 기능

### tsngen (TX)
- **10+ Gbps** 처리량 (sendmmsg 배치 전송)
- **Multi-TC 모드** - 8개 TC 동시 전송
- **VLAN PCP/DEI** 지원
- **tc/qdisc 연동** (SO_PRIORITY, PACKET_FANOUT)
- **토큰 버킷** 정밀 레이트 제한
- **패킷간 딜레이** (ns/us/ms 정밀도)

### tsnrecv (RX)
- **recvmmsg** 고속 배치 수신
- **PCP별 실시간 통계** - CBS/TAS 검증
- **VLAN 필터링** - 특정 VLAN/PCP만 캡처
- **시퀀스 추적** - 패킷 손실/순서 오류 감지
- **지연 측정** - tsngen 타임스탬프 기반
- **Inter-arrival time** - 패킷 간격 분석
- **CSV 출력** - 후처리 분석용

## 설치

```bash
make
sudo make install  # 선택
```

## 빠른 시작

```bash
# TX: 8개 TC 동시 전송
sudo ./tsngen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --multi-tc 0-7:100 -r 100

# RX: PCP별 통계 수집
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --duration 60

# 손실률/지연 측정
sudo ./tsngen eth0 -B IP -b MAC -Q 6:100 --seq --timestamp &
sudo ./tsnrecv eth1 --vlan 100 --seq --latency
```

## tsngen 옵션

```
Usage: tsngen [options] <interface>

Required:
  -B, --dst-ip IP          목적지 IP
  -b, --dst-mac MAC        목적지 MAC

Layer 2/3/4:
  -Q, --vlan [PCP[.DEI]:]VLAN  VLAN 태그 (예: 6:100, 6.1:100)
  -A, --src-ip IP|rand|IP-IP   소스 IP (범위 지원)
  -D, --dscp VALUE         DSCP 0-63
  -t, --type TYPE          udp, tcp, icmp, raw
  -p, --port PORT|PORT-PORT    포트 (범위 지원)

Traffic Control:
  -r, --rate MBPS          속도 제한
  --duration SEC           지속 시간
  --multi-tc TC[:VLAN]     멀티 TC 모드 (예: 0-7:100)
  -d, --delay DELAY        패킷간 딜레이 (100ns, 10us, 1ms)
  --skb-priority NUM       SO_PRIORITY (tc 연동)

Performance:
  --affinity               CPU 코어 고정
  --fanout[=MODE]          PACKET_FANOUT

Packet:
  --seq                    시퀀스 번호 삽입
  --timestamp              타임스탬프 삽입
  -l, --length SIZE|MIN-MAX    패킷 크기

Output:
  --stats-file FILE        CSV 통계 출력
  -R, --rx[=IFACE]         RX 통계 (손실률)
```

## tsnrecv 옵션

```
Usage: tsnrecv [options] <interface>

Filter:
  --vlan VID               VLAN ID 필터
  --pcp NUM                PCP 필터 (0-7)

Capture:
  --duration SEC           캡처 시간 (0=무한)
  --batch NUM              배치 크기 (기본: 256)

Analysis:
  --seq                    시퀀스 추적 (손실/순서 오류)
  --latency                지연 측정 (tsngen --timestamp 필요)
  --pcp-stats              PCP별 통계 표시

Output:
  --csv FILE               CSV 파일 출력
  -q, --quiet              조용히 실행
```

## 사용 예제

### 기본 트래픽 생성/수신

```bash
# TX: 1 Gbps UDP
sudo ./tsngen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 1000

# RX: 모든 트래픽 캡처
sudo ./tsnrecv eth1 --duration 60
```

### Multi-TC TSN 테스트

```bash
# TX: 8개 TC 동시 전송
sudo ./tsngen eth0 -B IP -b MAC --multi-tc 0-7:100 -r 100 --duration 60

# RX: PCP별 통계
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --duration 60
```

### CBS (Credit-Based Shaper) 검증

```bash
# TX: TC2, TC6 트래픽
sudo ./tsngen eth0 -B IP -b MAC --multi-tc 2,6:100 -r 500

# RX: 실제 수신량 확인
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --csv cbs_results.csv
```

### 손실률/지연 측정

```bash
# TX: 시퀀스 + 타임스탬프
sudo ./tsngen eth0 -B IP -b MAC -Q 6:100 --seq --timestamp -r 500

# RX: 분석
sudo ./tsnrecv eth1 --vlan 100 --pcp 6 --seq --latency
```

## 출력 예시

### tsngen

```
══════════════════════════════════════════════════════════════════════════════
 Multi-TC Mode: 8 Traffic Classes (PCP 0-7)
 VLAN: 100 | Rate: 100 Mbps/TC | Duration: 10 sec
══════════════════════════════════════════════════════════════════════════════

All 8 TCs completed.
```

### tsnrecv (PCP 통계)

```
════════════════════════════════════════════════════════════════════════════════
 tsnrecv v1.0.0 - TSN Traffic Receiver
 Interface: eth1 | Batch: 256 | VLAN: 100
════════════════════════════════════════════════════════════════════════════════
    Time │      Packets │        PPS │         Mbps │ PCP0  PCP1  PCP2  PCP3  PCP4  PCP5  PCP6  PCP7
─────────┼──────────────┼────────────┼──────────────┼─────────────────────────────────────────────────
    1.0s │       672000 │     672000 │       7916 │ 84000 84000 84000 84000 84000 84000 84000 84000
    2.0s │      1344000 │     672000 │       7916 │ 84000 84000 84000 84000 84000 84000 84000 84000
─────────┴──────────────┴────────────┴──────────────┴─────────────────────────────────────────────────

Summary:
  Duration:       2.00 seconds
  Total Packets:  1344000
  Avg Throughput: 7.916 Gbps

  PCP Distribution:
    PCP 0: 168000 pkts (12.5%), 988.2 Mbps avg
    PCP 1: 168000 pkts (12.5%), 988.2 Mbps avg
    ...
    PCP 7: 168000 pkts (12.5%), 988.2 Mbps avg

  Inter-arrival Time (us):
    Min: 0.8
    Avg: 1.5
    Max: 125.3
════════════════════════════════════════════════════════════════════════════════
```

## TSN 실험 워크플로우

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   tsngen    │────▶│ TSN Switch  │────▶│  tsnrecv    │
│    (TX)     │     │  CBS/TAS    │     │    (RX)     │
└─────────────┘     └─────────────┘     └─────────────┘
      │                                        │
      │  --multi-tc 0-7:100                   │  --pcp-stats
      │  --seq --timestamp                    │  --seq --latency
      │  -r 100 (Mbps/TC)                     │  --csv results.csv
      │                                        │
      └────────────────────────────────────────┘
              실험 결과 정량화 (CSV)
```

## 성능 튜닝

```bash
# 소켓 버퍼
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.rmem_max=67108864

# NIC 링버퍼
sudo ethtool -G eth0 tx 4096 rx 4096
```

## 버전 히스토리

### tsngen
- v1.4.0: PACKET_FANOUT, CPU Affinity, RX 통계
- v1.3.0: Multi-TC 모드
- v1.2.x: tc 연동, VLAN DEI, 딜레이
- v1.0.0: 초기 버전

### tsnrecv
- v1.0.0: 초기 버전 (recvmmsg, PCP 통계, 지연 분석)

## 라이선스

GPLv2

## 참고

- [Mausezahn (mz)](https://github.com/uweber/mausezahn)
- [IEEE 802.1Qav (CBS)](https://standards.ieee.org/)
- [IEEE 802.1Qbv (TAS)](https://standards.ieee.org/)
