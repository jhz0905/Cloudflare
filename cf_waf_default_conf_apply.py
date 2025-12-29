import requests  # Cloudflare API 호출을 위한 HTTP 요청 라이브러리

# WARNING: keep tokens safe.  # API 토큰은 외부 노출 금지
token = "Please insert your TOKEN"  # Cloudflare API Token
zone_id = "please insert your Zone ID"  # Cloudflare Zone ID (도메인 단위 고유 식별자)

# Set to True to apply changes. When False, the script prints what would change.
APPLY_CHANGES = True  # True면 실제 적용, False면 Dry-run(출력만)

# Add rules here. Leave the lists empty to skip.
NEW_CUSTOM_RULES = [  # WAF Custom Rules(http_request_firewall_custom)에 추가할 룰 목록
    {
        "action": "log",  # 트래픽을 차단하지 않고 로그만 기록
        "expression": '(cf.bot_management.score eq 1 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # Bot score 1 + 비인증 봇 + 정적 리소스 제외
        "description": "[EV] Definite bot traffic Score 1",  # 룰 설명
        "enabled": True,  # 룰 활성화
    },
    {
        "action": "log",  # 로그만 남김
        "expression": '(cf.bot_management.score ge 2 and cf.bot_management.score le 29 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # Bot score 2~29 범위
        "description": "[EV] Likely bot traffic score 2 ~ 29",  # 의심 봇 트래픽
        "enabled": True,  # 룰 활성화
    }
]

NEW_RATELIMIT_RULES = [  # Rate Limit(http_ratelimit)에 추가할 룰 목록
    {
        "action": "log",  # 차단 대신 로그
        "expression": '(not cf.bot_management.verified_bot)',  # Cloudflare 인증 봇 제외
        "description": "[EV] Origin Error Burst 10s 60Req",  # 10초 동안 에러 요청 폭주
        "enabled": True,  # 룰 활성화
        "ratelimit": {  # Rate Limit 세부 조건
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # PoP + 방문자 기준 식별
            "period": 10,  # 10초 기준
            "requests_per_period": 60,  # 60회 초과 시 트리거
            "mitigation_timeout": 600,  # 제한 지속 시간 600초
            "counting_expression": '(http.response.code in {400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 422 426 500 501 502 503 504 505 507 508 510 511})',  # 에러 응답 코드만 집계
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot)',  # 인증 봇 제외
        "description": "[EV] Origin Error AVG 1m 120Req",  # 1분 평균 에러 트래픽
        "enabled": True,  # 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 식별 기준
            "period": 60,  # 60초 기준
            "requests_per_period": 120,  # 120회 초과
            "mitigation_timeout": 600,  # 제한 유지 시간
            "counting_expression": '(http.response.code in {400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 422 426 500 501 502 503 504 505 507 508 510 511})',  # 에러 코드만 집계
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 + 정적 리소스 제외
        "description": "[EV] POST Request Burst 10s 50Req",  # POST 폭주 감지
        "enabled": True,  # 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 방문자 기준
            "period": 60,  # 기준 시간
            "requests_per_period": 50,  # POST 50회 초과
            "mitigation_timeout": 600,  # 제한 시간
            "counting_expression": '(http.request.method eq "POST")',  # POST 요청만 카운트
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 + 정적 리소스 제외
        "description": "[EV] POST Request AVG 1m 100Req",  # POST 평균 트래픽
        "enabled": True,  # 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 식별 기준
            "period": 60,  # 1분 기준
            "requests_per_period": 100,  # POST 100회 초과
            "mitigation_timeout": 600,  # 제한 시간
            "counting_expression": '(http.request.method eq "POST")',  # POST만 집계
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 + 정적 제외
        "description": "[EV] Page View Burst 10s 120Req",  # 페이지 조회 폭주
        "enabled": True,  # 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 식별 기준
            "period": 10,  # 10초 기준
            "requests_per_period": 120,  # 120회 초과
            "mitigation_timeout": 600,  # 제한 유지
            "counting_expression": '(http.request.method ne "POST")',  # POST 제외(페이지 뷰)
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 + 정적 제외
        "description": "[EV] Page View AVG 1m 250Req",  # 페이지 평균 트래픽
        "enabled": True,  # 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 식별 기준
            "period": 60,  # 1분 기준
            "requests_per_period": 250,  # 250회 초과
            "mitigation_timeout": 600,  # 제한 시간
            "counting_expression": '(http.request.method ne "POST")',  # 페이지 요청만
        },
    },
]

def api_headers():  # Cloudflare API 인증 헤더 생성 함수
    return {"Authorization": f"Bearer {token}"}  # Bearer 토큰 방식 인증

def get_ruleset(zone, ruleset_id):  # 특정 Ruleset 상세 조회
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"  # Ruleset 조회 URL
    resp = requests.get(url, headers=api_headers())  # GET 요청
    resp.raise_for_status()  # 오류 발생 시 예외
    return resp.json().get("result", {})  # 결과 반환

def merge_rules(existing_rules, new_rules):  # 기존 룰과 신규 룰 병합(중복 제거)
    existing_keys = {(r.get("description", ""), r.get("expression", ""), r.get("action", "")) for r in existing_rules}  # 중복 판별용 키
    merged = list(existing_rules)  # 기존 룰 복사
    for rule in new_rules:  # 신규 룰 반복
        key = (rule.get("description", ""), rule.get("expression", ""), rule.get("action", ""))  # 신규 룰 키
        if key in existing_keys:  # 중복일 경우
            print(f"skip duplicate rule: {rule.get('description', '(no description)')}")  # 스킵 로그
            continue
        merged.append(rule)  # 신규 룰 추가
        existing_keys.add(key)  # 키 등록
    return merged  # 병합 결과 반환

def update_ruleset(zone, ruleset, ruleset_id, merged_rules):  # Ruleset 업데이트 함수
    payload = {"name": ruleset.get("name", ""), "description": ruleset.get("description", ""), "kind": ruleset.get("kind", ""), "phase": ruleset.get("phase", ""), "rules": merged_rules}  # API 요청 바디
    if not APPLY_CHANGES:  # Dry-run 모드
        print(f"[DRY RUN] Would update ruleset {ruleset_id} with {len(merged_rules)} rules")  # 변경 예정 출력
        return None
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"  # 업데이트 URL
    resp = requests.put(url, headers=api_headers(), json=payload)  # PUT 요청
    if not resp.ok:  # 실패 시
        print(f"update failed: {resp.status_code} {resp.reason}")  # 상태 출력
        print(resp.text)  # 응답 본문 출력
    resp.raise_for_status()  # 예외 처리
    return resp.json()  # 결과 반환
