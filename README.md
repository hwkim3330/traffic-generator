# TSN Traffic Tools - tsngen & tsnrecv

고성능 TSN (Time-Sensitive Networking) 트래픽 생성 및 분석 도구.

## 도구 구성

| 도구 | 용도 | 핵심 기능 |
|------|------|----------|
| **tsngen** | 트래픽 생성 (TX) | sendmmsg 배치 전송, Multi-TC, VLAN PCP |
| **tsnrecv** | 트래픽 수신 (RX) | recvmmsg 배치 수신, PCP별 통계, 지연 분석 |

## 주요 기능

### tsngen (TX) v1.8.3
- **10+ Gbps** 처리량 (sendmmsg 배치 전송)
- **Multi-TC 모드** - 8개 TC 동시 전송
- **VLAN PCP/DEI** 지원
- **토큰 버킷** 정밀 레이트 제한
- **--rate-per-tc** - Multi-TC 레이트 정책 명확화
- **패킷간 딜레이** (ns/us/ms 정밀도)
- **CLOCK_MONOTONIC_RAW** 타임스탬프

### tsnrecv (RX) v1.3.1
- **recvmmsg** 고속 배치 수신
- **SO_RXQ_OVFL** - 커널 드롭 감지
- **PCP별 실시간 통계** - CBS/TAS 검증
- **Per-PCP 시퀀스 추적** - Multi-TC 손실 분석
- **VLAN 필터링** - 특정 VLAN/PCP만 캡처
- **지연 측정** - CLOCK_MONOTONIC_RAW 기반
- **CPU Affinity** - RX 스레드 코어 고정
- **표준화 CSV 스키마** - 자동화/후처리용

## 설치

```bash
make
sudo make install  # 선택
```

## 빠른 시작

```bash
# TX: 8개 TC 동시 전송 (100 Mbps/TC)
sudo ./tsngen eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 --multi-tc 0-7:100 -r 100 --rate-per-tc

# RX: PCP별 통계 수집 (CPU 2 고정)
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --affinity=2 --duration 60

# 손실률/지연 측정
sudo ./tsngen eth0 -B IP -b MAC -Q 6:100 --seq --timestamp &
sudo ./tsnrecv eth1 --vlan 100 --seq --latency --csv results.csv
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
  --rate-per-tc            Multi-TC에서 레이트는 TC당 (기본: 총합 분배)
  --duration SEC           지속 시간
  --multi-tc TC[:VLAN]     멀티 TC 모드 (예: 0-7:100)
  -d, --delay DELAY        패킷간 딜레이 (100ns, 10us, 1ms)
  --skb-priority NUM       SO_PRIORITY (tc 연동)

Performance:
  --affinity               CPU 코어 고정
  --fanout[=MODE]          PACKET_FANOUT

Packet:
  --seq                    시퀀스 번호 삽입
  --timestamp              타임스탬프 삽입 (CLOCK_MONOTONIC_RAW)
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
  --seq                    시퀀스 추적 (per-PCP for VLAN traffic)
  --latency                지연 측정 (tsngen --timestamp 필요)
  --pcp-stats              PCP별 통계 표시

Performance:
  --affinity[=CPU]         RX 스레드 CPU 고정 (기본: 0)

Output:
  --csv FILE               CSV 파일 출력 (표준화 스키마)
  -q, --quiet              조용히 실행
```

## 타임스탬프 정책

- **Clock**: `CLOCK_MONOTONIC_RAW` (NTP 영향 없음)
- **TX**: tsngen `--timestamp`로 payload에 ns 삽입
- **RX**: tsnrecv `--latency`로 수신 시각과 비교
- **제한**: TX/RX가 같은 머신에서 동작해야 정확한 지연 측정
- **Cross-machine**: PTP 동기화된 HW 타임스탬프 사용 필요

## TSN Payload 헤더 (v1.7.0+)

`--seq` 또는 `--timestamp` 사용 시 UDP payload에 구조화된 헤더 삽입:

### 새 포맷 (24 bytes, 기본)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic (0x54534E31 "TSN1")              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    Flags      |   Flow ID     |   Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Timestamp (ns, host order)                +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Payload Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Magic**: `0x54534E31` ("TSN1") - 포맷 식별
- **Flow ID**: `(TC << 4) | Worker` - per-flow 시퀀스 추적용
- **Flags**: SEQ(0x01), TIMESTAMP(0x02), FLOW_ID(0x04)

### 레거시 포맷 (12 bytes, `--legacy-payload`)

```
Bytes 0-3:  Sequence (network order)
Bytes 4-11: Timestamp (host order)
```

이전 버전 호환용.

### 시퀀스 번호 인코딩

```
Bits 31-29: TC (0-7)
Bits 28-24: Worker ID (0-15)
Bits 23-0:  Counter (~16M per worker)
```

예: TC2 Worker3 → 시퀀스 시작 = `0x23000000`

## 드롭 감지

tsnrecv는 `SO_RXQ_OVFL`을 사용하여 커널/소켓 드롭을 감지:

```
Summary:
  Kernel Drops:   0 (SO_RXQ_OVFL)
```

- **Drops > 0**: 수신 병목 발생 (버퍼 부족, CPU 부족)
- **해결**: `--affinity`, 소켓 버퍼 증가, 배치 크기 조정

## CSV 스키마

표준화된 CSV 컬럼 (자동화/후처리 호환):

```
time_s,total_pkts,total_pps,total_mbps,drops,
pcp0_pkts,pcp1_pkts,pcp2_pkts,pcp3_pkts,pcp4_pkts,pcp5_pkts,pcp6_pkts,pcp7_pkts,
latency_min_ns,latency_avg_ns,latency_max_ns,
iat_min_ns,iat_avg_ns,iat_max_ns
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
# TX: 8개 TC 동시 전송 (각 TC 100 Mbps)
sudo ./tsngen eth0 -B IP -b MAC --multi-tc 0-7:100 -r 100 --rate-per-tc --seq --timestamp

# RX: PCP별 통계 + per-PCP 시퀀스 추적
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --seq --affinity=2 --csv results.csv
```

### CBS (Credit-Based Shaper) 검증

```bash
# TX: TC2=1.5Mbps, TC6=3.5Mbps 목표
sudo ./tsngen eth0 -B IP -b MAC --multi-tc 2,6:100 -r 1500 --rate-per-tc &  # TC2
sudo ./tsngen eth0 -B IP -b MAC -Q 6:100 -r 3500 &  # TC6

# RX: 실제 수신량 확인 (CBS가 목표대로 shaping 했는지)
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --csv cbs_results.csv --duration 60
```

### TAS (Time-Aware Shaper) 검증

```bash
# TX: 모든 PCP 동시 전송 (gate pattern 확인용)
sudo ./tsngen eth0 -B IP -b MAC --multi-tc 0-7:100 -r 50 --rate-per-tc --seq --timestamp

# RX: inter-arrival time으로 gate open 구간 확인
sudo ./tsnrecv eth1 --vlan 100 --pcp-stats --latency --csv tas_results.csv
```

### 손실률/지연 측정

```bash
# TX: 시퀀스 + 타임스탬프
sudo ./tsngen eth0 -B IP -b MAC -Q 6:100 --seq --timestamp -r 500

# RX: per-PCP 시퀀스 분석 + 지연 측정
sudo ./tsnrecv eth1 --vlan 100 --pcp 6 --seq --latency
```

## 출력 예시

### tsngen (Multi-TC)

```
══════════════════════════════════════════════════════════════════════════════
 Multi-TC Mode: 8 Traffic Classes (PCP 0-7)
 VLAN: 100 | Rate: 100 Mbps/TC | Duration: 10 sec
 Clock: CLOCK_MONOTONIC_RAW (for timestamp)
══════════════════════════════════════════════════════════════════════════════

All 8 TCs completed.
```

### tsnrecv (PCP 통계 + 드롭)

```
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
 tsnrecv v1.1.0 - TSN Traffic Receiver
 Interface: eth1 | Batch: 256 | VLAN: 100 | CPU: 2
 Clock: CLOCK_MONOTONIC_RAW (for latency measurement)
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    Time │      Packets │        PPS │       Mbps │  Drops │   PCP0    PCP1    PCP2    PCP3    PCP4    PCP5    PCP6    PCP7
─────────┼──────────────┼────────────┼────────────┼────────┼───────────────────────────────────────────────────────────────────
    1.0s │       672000 │     672000 │     7916.0 │      0 │   84000   84000   84000   84000   84000   84000   84000   84000
─────────┴──────────────┴────────────┴────────────┴────────┴───────────────────────────────────────────────────────────────────

Summary:
  Duration:       1.00 seconds
  Total Packets:  672000
  Kernel Drops:   0 (SO_RXQ_OVFL)

  PCP Distribution:
    PCP 0: 84000 pkts (12.5%), 988.2 Mbps avg
    PCP 6: 84000 pkts (12.5%), 988.2 Mbps avg [seq_err:0 dup:0]
    ...

  Latency (us) [CLOCK_MONOTONIC_RAW]:
    Min: 12.3
    Avg: 45.6
    Max: 234.5
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
```

## TSN 실험 워크플로우

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   tsngen    │────▶│ TSN Switch  │────▶│  tsnrecv    │
│    (TX)     │     │  CBS/TAS    │     │    (RX)     │
└─────────────┘     └─────────────┘     └─────────────┘
      │                                        │
      │  --multi-tc 0-7:100                   │  --pcp-stats --seq
      │  --seq --timestamp                    │  --latency --affinity
      │  -r 100 --rate-per-tc                 │  --csv results.csv
      │                                        │
      └────────────────────────────────────────┘
              실험 결과 정량화 (CSV)
```

## 성능 튜닝

```bash
# 소켓 버퍼 (드롭 방지)
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.rmem_max=67108864

# NIC 링버퍼
sudo ethtool -G eth0 tx 4096 rx 4096

# CPU 고정 (RX 병목 방지)
sudo ./tsnrecv eth0 --affinity=2 ...

# 배치 크기 조정
sudo ./tsnrecv eth0 --batch 512 ...
```

## 한계 및 주의사항

### 성능 한계
- **64B 패킷 고PPS**: RX 병목 발생 가능 (affinity, batch, sysctl 필수)
- **RX 단일 스레드**: 수백 kpps 이상은 drop 확인 필수

### 측정 정확도
- **Cross-machine 지연**: 동일 머신에서만 정확 (PTP 미사용)
- **Drops > 0 시 Latency**: RX backlog로 인한 latency 왜곡 가능 (경고 출력)
- **Multi-TC fork 구조**: TC간 미세 jitter 발생 가능 (커널 스케줄링 영향)

### 시퀀스 추적
- **Multi-worker 모드**: 동일 PCP에 여러 worker가 다른 seq offset 사용
  - RX에서 interleaved sequences로 보임 → false reorder 가능
  - 정확한 seq 추적이 필요하면 `-w 1` 사용 권장
- **Multi-TC 모드**: TC별 100M offset으로 시퀀스 분리됨 (v1.6.0+)

### CSV 처리
- **Latency/IAT 비활성 시**: `-1` 출력 (0이 아님)
- **후처리 시 -1 값 필터링 필요**

## 버전 히스토리

### tsngen
- v1.8.3: flow_id별 seq 추적, VLAN/QinQ 파서 수정, unaligned read 제거
- v1.8.2: SO_PRIORITY/PACKET_FANOUT 제거 (의존성 간소화)
- v1.8.1: token_bucket g_running 체크, --pps 옵션 동작 수정
- v1.8.0: 버그 수정 - L4 체크섬 payload 반영, seq_num 이중 증가 수정, rand() thread-safe 변경
- v1.7.0: 표준 TSN payload 헤더 (24B), flow_id, --legacy-payload
- v1.6.0: Multi-TC 시퀀스 충돌 수정 (TC별 offset)
- v1.5.0: CLOCK_MONOTONIC_RAW, --rate-per-tc 옵션
- v1.4.0: CPU Affinity, RX 통계
- v1.3.0: Multi-TC 모드
- v1.2.x: tc 연동, VLAN DEI, 딜레이
- v1.0.0: 초기 버전

### tsnrecv
- v1.3.1: QinQ 지원, IHL 파싱, unaligned read 제거
- v1.3.0: TSN payload 헤더 v1 파싱, flow_id 지원, 레거시 호환
- v1.2.0: Latency 경고 (drops>0), CSV -1 처리, 버그 수정
- v1.1.0: SO_RXQ_OVFL 드롭 감지, CLOCK_MONOTONIC_RAW, per-PCP 시퀀스, CPU affinity, CSV 스키마 표준화
- v1.0.0: 초기 버전 (recvmmsg, PCP 통계, 지연 분석)

## 라이선스

GPLv2

## 참고

- [Mausezahn (mz)](https://github.com/uweber/mausezahn)
- [IEEE 802.1Qav (CBS)](https://standards.ieee.org/)
- [IEEE 802.1Qbv (TAS)](https://standards.ieee.org/)
