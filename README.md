# 🛡️ InfraRed - Python + C++ Hybrid Antivirus

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/C++-17-orange.svg" alt="C++">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License">
</p>


---

## 📋 버전 정보

### V2.0 (Current)

#### 1. 🔍 다중 탐지 엔진
| 탐지 방식 | 설명 |
|-----------|------|
| **시그니처 기반** | 악성코드 특유의 바이트 패턴 매칭 |
| **해시 기반** | MD5/SHA256 해시값으로 알려진 악성코드 식별 |
| **YARA 룰** | YARA 룰 형식 지원 |
| **휴리스틱 분석** | 엔트로피 계산으로 패킹/암호화된 파일 탐지 |

#### 2. 📂 스캔 옵션
- 파일/폴더 선택 검사
- 전체 시스템 검사
- 특정 드라이브 검사
- 모든 드라이브 검사
- USB 드라이브 검사
- 빠른 스캔 (다운로드, 문서, 바탕화면)

#### 3. 👁️ 실시간 모니터링
- 특정 폴더 감시 기능
- 새 파일 생성 시 자동 스캔

#### 4. 🔒 격리 기능
- 악성 파일 자동/수동 격리
- 격리된 파일 복원 기능
- 격리 파일 완전 삭제
- 원본 경로 확인

#### 5. 🔬 고급 분석 도구
- PE 파일 구조 분석
- Import API 분석
- 압축 파일 내부 검사

#### 6. ⚙️ 사용자 편의 기능
- 다크모드 지원
- 검사 제외 설정 (폴더/파일/확장자/해시)
- 설정 저장 및 불러오기
- 스캔 결과 통계 차트
- 스캔 히스토리

---

### V1.0

Python과 C++를 결합한 데모 백신입니다. 단어 필터링 기반의 간단한 탐지 구조입니다.

---

## 🏗️ 프로젝트 구조

```
InfraRed/
├── cpp_engine/
│   ├── antivirus_core.cpp      # C++ 탐지 엔진 소스
│   ├── build.bat               # 빌드 스크립트
│   └── CMakeLists.txt
├── python_gui/
│   ├── antivirus.py            # 메인 GUI 애플리케이션
│   ├── requirements.txt        # Python 의존성
│   └── quarantine/             # 격리 폴더
├── test_files/
│   └── create_test_virus_files.py
└── README.md
```

---

## 🚀 설치 방법

### 요구 사항
- Windows 10/11
- Python 3.8+
- Visual Studio 2019+ (C++ 빌드용)
- MinGW-w64 (대안)

### 1. Python 의존성 설치

```bash
pip install -r python_gui/requirements.txt
```

또는

```bash
pip install PyQt5 watchdog pyqtchart
```

### 2. C++ 엔진 빌드

```bash
cd cpp_engine
build.bat
```

빌드 완료 후 `antivirus_core.dll`이 생성됩니다.

### 3. 실행

```bash
cd python_gui
python antivirus.py
```

---

## 🔧 기술 스택

### Frontend (Python)
- **PyQt5** - GUI 프레임워크
- **PyQtChart** - 차트 시각화
- **watchdog** - 파일 시스템 모니터링

### Backend (C++)
- **Windows API** - 파일 시스템 접근
- **PE Parser** - 실행 파일 분석
- **Custom Engine** - 시그니처/해시 매칭

### 통신
- **ctypes** - Python-C++ DLL 바인딩

---

## ⚠️ 주의사항

> - 실제 악성코드 탐지에는 한계가 있습니다
> - 상용 백신 소프트웨어를 대체할 수 없습니다

---

## 📝 라이선스

Apache License 2.0

---


