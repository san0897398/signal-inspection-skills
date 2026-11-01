# 신호제어 검사 문제 조사 스킬

검사 중 장비가 응답하지 않거나 화면과 실제 상태가 다를 때, 어디에서 문제가 시작되는지 LLM과 확인하기 위해 정리한 작업 절차입니다.

실무에서 사용한 `ctrl-probe`를 공개용으로 구성했습니다. 현재 증상에서 가까운 입력·출력부터 확인하고, 센터·시험 PC·제어기의 코드와 기록을 필요한 순서로 읽도록 안내합니다. 접속 성공, 요청 송신, 응답 수신, 화면 표시를 구분해 조사합니다.

## 구성

- [스킬 원문](skills/ctrl-probe/SKILL.md)
- [환경 연결 항목](skills/ctrl-probe/ACCESS.md): 실제 주소·계정·키 경로는 마스킹하고 실행 시 지정합니다.
- [수집기](skills/ctrl-probe/scripts/observe.py): 두 장비의 TCP 패킷을 수집하고 오프라인에서 재조립·비교합니다.
- [해석 범위](skills/ctrl-probe/references/protocol.md)

`skills/ctrl-probe` 폴더를 사용하는 에이전트의 스킬 디렉터리에 복사해 사용할 수 있습니다. 장비 연결과 관측은 해당 환경의 승인된 권한과 설정이 필요합니다.

## 로컬 검증

```sh
python3 -m unittest discover -s tests -v
python3 skills/ctrl-probe/scripts/observe.py --help
```

테스트는 문서용 주소와 합성 패킷을 사용합니다. 실계정·검사 장비·업무 네트워크에 접속하지 않습니다. 업무 원본과 실제 관측 로그는 포함하지 않았습니다.

라이선스는 [Apache-2.0](LICENSE)입니다.
