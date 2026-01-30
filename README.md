# trafgen - High-Performance Traffic Generator

mz (Mausezahn) 기반 고성능 네트워크 트래픽 생성기. 1Gbps 이상의 트래픽 생성 지원.

## 설치

### 1. mz (Mausezahn) 설치

```bash
# Ubuntu/Debian
sudo apt-get install netsniff-ng

# RHEL/CentOS
sudo yum install netsniff-ng

# Arch Linux
sudo pacman -S netsniff-ng
```

### 2. trafgen 설치

```bash
git clone https://github.com/hwkim3330/traffic-generator.git
cd traffic-generator
chmod +x trafgen presets.sh

# 시스템에 설치 (선택)
sudo cp trafgen /usr/local/bin/
```

## 사용법

### 기본 사용

```bash
# 최대 속도 UDP 트래픽
sudo ./trafgen -i eth0 -d 192.168.1.100 -m 00:11:22:33:44:55

# 1Gbps 트래픽
sudo ./trafgen -i eth0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 1000

# 60초간 테스트
sudo ./trafgen -i eth0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 1000 -t 60
```

### 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-i, --interface` | 네트워크 인터페이스 | (필수) |
| `-d, --dst-ip` | 목적지 IP | (필수) |
| `-m, --dst-mac` | 목적지 MAC | (필수) |
| `-r, --rate` | 목표 속도 (Mbps), 0=최대 | 0 |
| `-t, --duration` | 지속 시간 (초) | 무한 |
| `-n, --streams` | 병렬 스트림 수 | 1 |
| `-l, --length` | 패킷 크기 (bytes) | 1472 |
| `-p, --port` | 목적지 포트 | 5001 |
| `-T, --proto` | 프로토콜 (udp/tcp/icmp) | udp |
| `-v, --vlan` | VLAN ID (1-4094) | 없음 |
| `-q, --vlan-prio` | VLAN Priority (0-7) | 0 |
| `-D, --dscp` | DSCP 값 (0-63) | 0 |

### 예제

#### 속도 조절
```bash
# 500 Mbps
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 500

# 2 Gbps (멀티 스트림)
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 2000 -n 4
```

#### 패킷 크기
```bash
# 소형 패킷 (64 bytes) - 높은 pps
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -l 64

# 점보 프레임 (9000 bytes)
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -l 9000
```

#### VLAN 태깅
```bash
# VLAN 100, Priority 5
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -v 100 -q 5
```

#### QoS (DSCP)
```bash
# DSCP EF (46) - VoIP
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -D 46

# DSCP AF41 (34) - Video
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -D 34
```

#### TCP SYN
```bash
# TCP SYN to port 80
sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -T tcp -p 80
```

## Presets (프리셋)

자주 사용하는 패턴을 함수로 제공:

```bash
source presets.sh

# UDP flood
udp_flood enp11s0 192.168.1.100 00:11:22:33:44:55

# TCP SYN flood to port 80
tcp_syn_flood enp11s0 192.168.1.100 00:11:22:33:44:55 80

# High pps (small packets)
small_pkt_flood enp11s0 192.168.1.100 00:11:22:33:44:55

# VLAN traffic
vlan_traffic enp11s0 192.168.1.100 00:11:22:33:44:55 100 5 1000

# VoIP simulation (DSCP EF)
voip_traffic enp11s0 192.168.1.100 00:11:22:33:44:55 100

# Multi-stream (4 streams)
multi_stream enp11s0 192.168.1.100 00:11:22:33:44:55 4

# Bandwidth ramp test
bandwidth_ramp enp11s0 192.168.1.100 00:11:22:33:44:55 1000 100 5
```

## TSN 테스트

### CBS (Credit-Based Shaper) 테스트

```bash
source presets.sh

# TC2 트래픽 (PCP 4, 1.5 Mbps)
tsn_tc2 enp11s0 192.168.1.100 00:11:22:33:44:55 100

# TC6 트래픽 (PCP 0, 3.5 Mbps)
tsn_tc6 enp11s0 192.168.1.100 00:11:22:33:44:55 100
```

### TAS (Time-Aware Shaper) 테스트

```bash
# 여러 우선순위 트래픽 동시 생성
for prio in 0 1 2 3 4 5 6 7; do
    sudo ./trafgen -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 \
        -v 100 -q $prio -r 100 -P $((10000 + prio * 100)) &
done
```

## 수신 측 확인

```bash
# iperf3 서버
iperf3 -s -p 5001

# tcpdump로 패킷 확인
sudo tcpdump -i eth0 -n udp port 5001

# 패킷 카운트
sudo tcpdump -i eth0 -n udp port 5001 -c 100 -q
```

## 성능 튜닝

### 시스템 설정

```bash
# 소켓 버퍼 증가
sudo sysctl -w net.core.wmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864
sudo sysctl -w net.core.rmem_max=67108864

# NIC 링버퍼 증가
sudo ethtool -G eth0 tx 4096 rx 4096
```

### 높은 처리량

```bash
# 멀티 스트림 + 큰 패킷
sudo ./trafgen -i eth0 -d 192.168.1.100 -m 00:11:22:33:44:55 \
    -n 4 -l 1472 -r 0
```

## 파일 구조

```
traffic-generator/
├── trafgen          # 메인 트래픽 생성기
├── presets.sh       # 프리셋 함수
├── config.yaml      # 설정 파일 예시
└── README.md
```

## License

MIT License

## References

- [mz (Mausezahn)](https://man7.org/linux/man-pages/man8/mausezahn.8.html)
- [netsniff-ng toolkit](http://netsniff-ng.org/)
