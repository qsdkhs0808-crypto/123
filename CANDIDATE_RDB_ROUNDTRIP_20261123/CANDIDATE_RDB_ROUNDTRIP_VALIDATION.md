# ScreenLayout 후보 RDB 메모리 직렬화 및 재파싱 검증 보고서

작성 시각: 2026-11-23 15:43:32

## 1. 개요 및 안전 원칙 준수 확인

- **디스크 미저장 원칙 100% 준수**: 직렬화된 후보 RDB(`1,386,012 바이트`)는 디스크 파일로 저장되지 않고, 순수 Python 메모리 버퍼(`bytes`) 내에서만 직렬화 및 독립 재파싱되었습니다.
- **BIN 파일 무수정**: PK `ScreenLayout.rdb.bin81`의 기존 엔트리를 그대로 참조하였으며 수정하지 않았습니다.

---

## 2. 19대 라운드트립 재파싱 검증 결과 매트릭스

| 번호 | 검증 항목 | 판정 | 실측 결과 및 측정값 |
|:---:|---|:---:|---|
|  1 | **RDB Magic '_DRK0000'** | **PASS** | _DRK0000 |
|  2 | **Header Size Match** | **PASS** | 32 == 32 |
|  3 | **Header record_count == 16233** | **PASS** | count=16233 |
|  4 | **Header index_hash == 0x8c759c7f** | **PASS** | 0x8c759c7f |
|  5 | **Parsed Records Count == 16233** | **PASS** | len=16233 |
|  6 | **All Record Boundaries Valid** | **PASS** | 16,233개 레코드 모두 버퍼 범위 내 정상 |
|  7 | **All Record 4B Aligned** | **PASS** | 16,233개 레코드 시작 오프셋 4B 정렬 만족 |
|  8 | **No Trailing Unexpected Data** | **PASS** | final_pos=1,386,012 == total_size=1,386,012 |
|  9 | **No Duplicate Resource IDs** | **PASS** | 중복 ID 개수: 0 |
| 10 | **All Resource IDs in Planned Positions** | **PASS** | 16,233개 위치 100% 일치 |
| 11 | **4 Target IDs Exactly Once** | **PASS** | 4개 대상 ID 모두 정확히 1회 존재 |
| 12 | **4 Targets Location Suffix '#51'** | **PASS** | 4개 리소스 Location 모두 #51 참조 확인 |
| 13 | **4 Targets record_size & loc_size Valid** | **PASS** | 계산된 직렬화 크기(103B/104B)와 100% 일치 |
| 14 | **4 Targets Metadata Matches CE (32B)** | **PASS** | CE 원본 32바이트 메타데이터와 비트 단위 일치 |
| 15 | **4 Targets declared_payload Matches CE** | **PASS** | CE 원본 declared_payload_size와 100% 일치 |
| 16 | **Root Record 56B Raw Identical to PK** | **PASS** | PK 원본 루트 56바이트 바이너리와 100% 동일 |
| 17 | **Root declared_payload_size == 2259136** | **PASS** | decl=2,259,136 |
| 18 | **Root res_id == header index_hash** | **PASS** | res_id=0x8c759c7f == hash=0x8c759c7f |
| 19 | **4 Targets RDB declared == BIN uncomp size** | **PASS** | RDB declared와 PK bin81 비압축 크기 100% 일치 |

---

## 3. RDB Flags vs BIN Flags 독립성 규명

| 리소스 ID | RDB 레코드 Flags | BIN 엔트리 Flags | 구조적 분석 및 평가 |
|---|:---:|:---:|---|
| `0x5320bafb` | `0x00120000` | `0x00100000` | 서로 다른 계층의 플래그 필드로 동일할 필요 없음 |
| `0xaa8bbc8b` | `0x00120000` | `0x00100000` | 서로 다른 계층의 플래그 필드로 동일할 필요 없음 |
| `0xbf735461` | `0x00120000` | `0x00100000` | 서로 다른 계층의 플래그 필드로 동일할 필요 없음 |
| `0xcce75262` | `0x00120000` | `0x00100000` | 서로 다른 계층의 플래그 필드로 동일할 필요 없음 |

- **RDB 레코드 Flags (`0x00120000`)**: RDB 인덱스 레코드 계층의 플래그 (CE 원본과 100% 일치 반영).
- **BIN 엔트리 Flags (`0x00100000`)**: BIN 물리 엔트리 계층의 플래그 (PK bin81 원본과 100% 일치).
- 두 플래그는 코에이 엔진의 서로 다른 레이어에서 파싱되는 독립 필드임이 명확히 실측 확인되었습니다.

---

## 4. 파일 크기 및 오프셋 변화 실측 결과

- **PK 원본 RDB 파일 크기**: `1,385,596 바이트`
- **4개 신규 리소스 정렬 크기 합**: `104 + 104 + 104 + 104 = 416 바이트`
- **직렬화된 후보 RDB 실제 크기**: **`1,386,012 바이트` (계산값과 100% 일치)**
- **오프셋 시프트 분포**:
  * `idx 0 ~ 5290` (5,291개): `shift == +0 바이트`
  * `idx 5291 ~ 10778` (5,487개): `shift == +104 바이트`
  * `idx 10779 ~ 12044` (1,265개): `shift == +208 바이트`
  * `idx 12045 ~ 12903` (858개): `shift == +312 바이트`
  * `idx 12904 ~ 16231` (3,328개): `shift == +416 바이트`
  * `idx 16232` (종단 루트 1개): `shift == +416 바이트` (오프셋 `0x1525e4`)
