# 작업 환경 연결

실제 네트워크 주소·사용자명·키 경로·장치 매핑은 공개본에서 제거했습니다. 아래 값은 권한을 부여받은 작업 환경의 로컬 설정에서 지정합니다.

| 항목 | 필요한 값 |
| --- | --- |
| `CENTER_SSH` | 기존 SSH 설정의 센터 별칭 |
| `CENTER_HOST` / `CENTER_USER` | 접속 뒤 대조할 실제 호스트명·사용자명 |
| `CENTER_TCP_PORT` | 관측 대상 센터 TCP 포트 |
| `REFERENCE_IP` / `TARGET_IP` | 비교할 두 장비의 현재 주소 |
| 협업 기록 위치 | 해당 환경의 README·CURRENT·실험별 기록 |
| CAN 로그 위치 | 기존 수집기가 보존한 각 채널의 로그 |
| Windows 관측 연결 | 해당 환경에서 승인한 UI·직렬·USB 관측 도구 |

SSH 키와 중계 설정은 운영자가 관리하는 기존 SSH 설정을 사용합니다. 이 저장소는 계정 생성·권한 부여·키 등록을 수행하지 않습니다.

## 현재 신원과 실행 세대 확인

수집기는 기대한 호스트명·사용자명과 실제 접속 결과가 일치해야 패킷 수집을 시작합니다. 키 인증과 기존 host trust를 사용하며, 새 대상의 키를 자동 신뢰하지 않습니다.

아래 명령의 상대 경로는 `ctrl-probe` 스킬 폴더 기준입니다.

```sh
python3 scripts/observe.py capture \
  --ssh "${CENTER_SSH:?}" \
  --expected-host "${CENTER_HOST:?}" \
  --expected-user "${CENTER_USER:?}" \
  --tcp-port "${CENTER_TCP_PORT:?}" \
  --peer "1=${REFERENCE_IP:?}" --peer "2=${TARGET_IP:?}" \
  --seconds 60 --out captures/new-observation
```

접속 환경의 명령 실행 권한과 패킷 수집 권한은 별도로 확인합니다. 이 명령은 이미 허용된 관측에 사용하며, 제어기 명령·설정 변경·재기동 권한을 부여하지 않습니다.

## 이미 수집된 자료 사용

CAN·직렬 수집기가 연결돼 있으면 그 로그의 해당 시험 구간을 읽습니다. 단일 클라이언트 포트에 새 연결을 추가하지 않습니다. 채널 이름만으로 물리 어댑터와 장비 대응을 확정하지 않고 연결·시계·drop 기록을 함께 확인합니다.

```sh
python3 scripts/observe.py analyze captures/new-observation
```

관측 결과에는 실제 주소와 원문 패킷이 남으므로 작업 환경에 보관합니다. `captures/`는 Git에서 제외하며 이 공개 저장소에는 합성 테스트만 포함합니다.
