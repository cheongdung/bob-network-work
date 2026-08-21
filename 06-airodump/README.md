# airodump

## 과제

`airodump-ng`와 비슷하게 주변 AP 정보를 출력하는 프로그램이다.

Beacon frame에서 다음 정보를 수집한다.

- BSSID
- PWR
- Beacons
- #Data
- CH
- ENC
- ESSID

## 빌드

```bash
qmake airodump.pro
make
```

## 실행

```text
syntax : airodump <interface>
sample : airodump wlan0
```

무선 인터페이스는 monitor mode 상태여야 한다.

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iw dev
sudo ./airodump wlan0
```

`airmon-ng` 실행 후 인터페이스 이름이 `wlan0mon`으로 바뀌었다면 마지막 인자도 `wlan0mon`으로 변경한다.

## 실행 결과
<video src="https://github.com/user-attachments/assets/e2c80b12-8983-42f7-acb8-e2613ca202d6"
controls 
width="100%">
</video>


