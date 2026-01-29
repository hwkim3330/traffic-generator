# High-Performance Traffic Generator

1Gbps 이상의 네트워크 트래픽을 생성할 수 있는 고성능 트래픽 생성기.

## Features

- **1Gbps+ 트래픽 생성** - sendmmsg() 배치 전송으로 최대 10Gbps까지 지원
- **다중 워커** - 멀티스레드/멀티프로세스 아키텍처
- **VLAN 태깅** - 802.1Q VLAN 지원 (ID + Priority)
- **QoS 마킹** - DSCP 값 설정
- **유연한 설정** - CLI 옵션 또는 YAML 설정 파일
- **실시간 통계** - pps, throughput, 에러 모니터링

## Requirements

### Ubuntu/Debian
```bash
# mz (Mausezahn) 설치 - wrapper script용
sudo apt-get install netsniff-ng

# C 버전 빌드용
sudo apt-get install build-essential
```

### RHEL/CentOS
```bash
sudo yum install netsniff-ng gcc make
```

## Quick Start

### 1. 빌드 (C 버전)
```bash
make
```

### 2. 실행

#### mz Wrapper (trafgen.sh)
```bash
# 최대 속도 트래픽
sudo ./trafgen.sh -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55

# 1Gbps 트래픽
sudo ./trafgen.sh -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 1000

# 멀티 스트림 (더 높은 처리량)
sudo ./trafgen.sh -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -w 4 -r 4000
```

#### C 버전 (traffic_gen)
```bash
# 최대 속도 트래픽
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55

# 1Gbps, 1024바이트 패킷
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 1000 -l 1024

# 10초 테스트, VLAN 태깅
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -t 10 -v 100 -q 5
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | 네트워크 인터페이스 | (필수) |
| `-d, --dst-ip` | 목적지 IP | (필수) |
| `-m, --dst-mac` | 목적지 MAC | (필수) |
| `-s, --src-ip` | 출발지 IP | 인터페이스 IP |
| `-p, --dst-port` | 목적지 포트 | 5001 |
| `-P, --src-port` | 출발지 포트 | 10000 |
| `-l, --length` | 패킷 크기 (bytes) | 1472 |
| `-r, --rate` | 목표 속도 (Mbps), 0=최대 | 0 |
| `-t, --duration` | 지속 시간 (초), 0=무한 | 0 |
| `-w, --workers` | 워커 수 | CPU 코어 수 |
| `-b, --batch` | 배치 크기 | 1024 |
| `-v, --vlan` | VLAN ID (1-4094) | 없음 |
| `-q, --vlan-prio` | VLAN Priority (0-7) | 0 |
| `-D, --dscp` | DSCP 값 (0-63) | 0 |

## Usage Examples

### 기본 UDP 트래픽
```bash
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55
```

### 특정 속도로 트래픽 생성
```bash
# 500 Mbps
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 500

# 2 Gbps (2000 Mbps)
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 2000 -w 4
```

### 패킷 크기 조절
```bash
# 소형 패킷 (64 bytes) - 높은 pps
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -l 64

# 점보 프레임 (9000 bytes)
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -l 9000
```

### VLAN 태깅
```bash
# VLAN 100, Priority 5
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -v 100 -q 5
```

### QoS DSCP 마킹
```bash
# DSCP EF (46) for VoIP
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -D 46

# DSCP AF41 (34) for Video
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -D 34
```

### 수신측에서 트래픽 확인
```bash
# iperf3 서버 (목적지에서)
iperf3 -s -p 5001

# tcpdump로 확인
sudo tcpdump -i enp15s0 -n udp port 5001
```

## Performance Tuning

### 높은 처리량을 위한 설정

1. **워커 수 증가**
```bash
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -w 8
```

2. **큰 패킷 사용** (처리량 최대화)
```bash
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -l 1472
```

3. **배치 크기 조절**
```bash
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -b 2048
```

4. **시스템 튜닝**
```bash
# 소켓 버퍼 증가
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864

# 네트워크 큐 증가
sudo ethtool -G enp11s0 tx 4096
```

## Output Example

```
================================================================================
Traffic Generator - 4 workers, 1472 byte packets
================================================================================
    Time |        Packets |   Rate (pps) |      Throughput |     Errors
--------------------------------------------------------------------------------
    1.0s |        847,293 |      847,293 |        9.97 Gbps |          0
    2.0s |      1,694,521 |      847,228 |        9.97 Gbps |          0
    3.0s |      2,541,803 |      847,282 |        9.97 Gbps |          0
--------------------------------------------------------------------------------

Final Summary:
  Duration:       3.00 seconds
  Total Packets:  2,541,803
  Total Data:     3.564 GB
  Avg Rate:       847,268 pps
  Avg Throughput: 9.971 Gbps
  Errors:         0
================================================================================
```

## TSN Testing

TSN (Time-Sensitive Networking) 테스트용 사용 예시:

### CBS (Credit-Based Shaper) 테스트
```bash
# TC2 트래픽 (PCP 4-7 -> Priority 2)
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -v 100 -q 4 -r 1500

# TC6 트래픽 (PCP 0-3 -> Priority 6)
sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -v 100 -q 0 -r 3500
```

### TAS (Time-Aware Shaper) 테스트
```bash
# 여러 우선순위의 트래픽을 동시에 생성
for prio in 0 1 2 3 4 5 6 7; do
    sudo ./traffic_gen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 \
        -v 100 -q $prio -r 100 -P $((10000 + prio * 100)) &
done
```

## Files

| File | Description |
|------|-------------|
| `traffic_generator.c` | C 기반 고성능 트래픽 생성기 |
| `trafgen.sh` | mz (Mausezahn) wrapper 스크립트 |
| `config.yaml` | 설정 파일 예시 |
| `Makefile` | 빌드 스크립트 |

## References

- [Mausezahn (mz)](https://github.com/uweber/mausezahn) - 참고한 트래픽 생성기
- [netsniff-ng](http://netsniff-ng.org/) - mz가 포함된 툴킷
- [Linux sendmmsg()](https://man7.org/linux/man-pages/man2/sendmmsg.2.html) - 배치 패킷 전송

## License

MIT License
