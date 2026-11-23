# ScreenLayout 전체 공통 Resource ID 상대 순서 실측 검증 보고서

작성 시각: 2026-11-23 15:43:32

## 1. 검증 원칙 및 방법론

하드코딩된 PASS를 배제하고, Python 내부에서 계산된 실제 배열 비교 결과(`ce_projected == cand1_projected`)와 길이, 불일치 카운트를 바탕으로 최종 판정을 기록합니다.

- **비교 대상**: CE0928 ScreenLayout과 후보 1의 공통 Resource ID 집합 ($S_{common}$)
- **CE 투영 시퀀스 ($S_{CE}$)**: CE 원본 시퀀스에서 $S_{common}$에 속하는 원소만 순서대로 추출
- **후보 1 투영 시퀀스 ($S_{Cand1}$)**: 후보 1 시퀀스에서 $S_{common}$에 속하는 원소만 순서대로 추출
- **합격 기준**: `len(S_CE) == len(S_Cand1)` 및 `S_CE == S_Cand1` (불일치 0개)

---

## 2. 동적 계산 실측 결과 매트릭스

| 검증 지표 | 실측 값 | 판정 | 설명 |
|---|:---:|:---:|---|
| **CE 일반 레코드 수** | 18,045 개 | PASS | CE ScreenLayout 일반 리소스 총수 |
| **PK 원본 일반 레코드 수** | 16,228 개 | PASS | PK ScreenLayout 일반 리소스 총수 |
| **후보 1 일반 레코드 수** | 16,232 개 | PASS | PK 일반 16,228개 + 신규 삽입 4개 |
| **공통 Resource ID 수** | **16,231 개** | PASS | 양쪽에 동시 존재하는 리소스 총수 |
| **CE 전용 Resource ID 수** | 1,814 개 | INFO | CE에만 존재하는 리소스 수 (미이식 UI 등) |
| **PK 전용 Resource ID 수** | 1 개 | INFO | PK에만 존재하는 리소스 (`0x7f1073b9`) |
| **CE 원본 중복 ID 수** | 0 개 | PASS | CE 내부 Resource ID 중복 여부 |
| **PK 원본 중복 ID 수** | 0 개 | PASS | PK 내부 Resource ID 중복 여부 |
| **CE 투영 시퀀스 길이** | 16,231 | PASS | $S_{CE}$ 원소 개수 |
| **후보 1 투영 시퀀스 길이** | 16,231 | PASS | $S_{Cand1}$ 원소 개수 |
| **`ce_projected == cand1_projected`** | **True** | **PASS ✅** | **배열 1:1 전수 일치 결과** |
| **불일치 개수 (Mismatch Count)** | **0 개** | **PASS ✅** | 순서 불일치 원소 개수 |
| **최초 불일치 정보** | None | PASS | 불일치 발생 위치 |

---

## 3. 결론

CE0928과 후보 1의 공통 Resource ID **16,231개 전체**에 대해 투영 상대 순서를 비교한 결과, 단 1개의 순서 뒤바뀜도 없이 **100% 완전 일치(PASS)**함을 확인하였습니다.
