import requests  # Cloudflare REST API 호출을 위한 HTTP 라이브러리

# WARNING: keep tokens safe.  # API 토큰 보안 주의
token = "Please insert your TOKEN"  # Cloudflare API Bearer Token
zone_id = "please insert your Zone ID"  # Cloudflare Zone ID (도메인 단위 고유 ID)

# Set to True to apply changes. When False, the script prints what would change.
APPLY_CHANGES = True  # True면 실제 룰 적용, False면 Dry-run(출력만)

# Add rules here. Leave the lists empty to skip.
NEW_CUSTOM_RULES = [  # WAF Custom Rules(http_request_firewall_custom)에 추가할 룰 목록
    {
        "action": "log",  # 차단하지 않고 로그만 기록
        "expression": '(cf.bot_management.score eq 1 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # Bot score 1 + 인증 봇 제외 + 정적 리소스 제외
        "description": "[EV] Definite bot traffic Score 1",  # 확실한 봇 트래픽 식별용 설명
        "enabled": True,  # 룰 활성화
    },
    {
        "action": "log",  # 로그만 기록
        "expression": '(cf.bot_management.score ge 2 and cf.bot_management.score le 29 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # Bot score 2~29 범위
        "description": "[EV] Likely bot traffic score 2 ~ 29",  # 의심 봇 트래픽 설명
        "enabled": True,  # 룰 활성화
    }
]

NEW_RATELIMIT_RULES = [  # Rate Limit(http_ratelimit)에 추가할 룰 목록
    {
        "action": "log",  # 차단 없이 로그 기록
        "expression": '(not cf.bot_management.verified_bot)',  # Cloudflare 인증 봇 제외
        "description": "[EV] Origin Error Burst 10s 60Req",  # 에러 응답 폭주 탐지
        "enabled": True,  # 룰 활성화
        "ratelimit": {  # Rate Limit 상세 설정
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # PoP + 방문자 단위로 식별
            "period": 10,  # 10초 기준
            "requests_per_period": 60,  # 60회 초과 시 트리거
            "mitigation_timeout": 600,  # 제한 유지 시간(초)
            "counting_expression": '(http.response.code in {400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 422 426 500 501 502 503 504 505 507 508 510 511})',  # 에러 응답 코드만 카운트
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot)',  # 인증 봇 제외
        "description": "[EV] Origin Error AVG 1m 120Req",  # 1분 평균 에러 요청 탐지
        "enabled": True,  # 룰 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 방문자 식별 기준
            "period": 60,  # 60초 기준
            "requests_per_period": 120,  # 120회 초과 시 트리거
            "mitigation_timeout": 600,  # 제한 유지 시간
            "counting_expression": '(http.response.code in {400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 422 426 500 501 502 503 504 505 507 508 510 511})',  # 에러 코드만 집계
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 및 정적 리소스 제외
        "description": "[EV] POST Request Burst 10s 50Req",  # POST 요청 폭주 탐지
        "enabled": True,  # 룰 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 방문자 기준
            "period": 60,  # 기준 시간
            "requests_per_period": 50,  # POST 50회 초과
            "mitigation_timeout": 600,  # 제한 시간
            "counting_expression": '(http.request.method eq "POST")',  # POST 요청만 집계
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 및 정적 제외
        "description": "[EV] POST Request AVG 1m 100Req",  # POST 평균 트래픽 탐지
        "enabled": True,  # 룰 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 방문자 식별
            "period": 60,  # 1분 기준
            "requests_per_period": 100,  # POST 100회 초과
            "mitigation_timeout": 600,  # 제한 유지
            "counting_expression": '(http.request.method eq "POST")',  # POST 요청만 집계
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 및 정적 제외
        "description": "[EV] Page View Burst 10s 120Req",  # 페이지 조회 폭주 탐지
        "enabled": True,  # 룰 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 방문자 단위
            "period": 10,  # 10초 기준
            "requests_per_period": 120,  # 120회 초과
            "mitigation_timeout": 600,  # 제한 시간
            "counting_expression": '(http.request.method ne "POST")',  # POST 제외(페이지 뷰)
        },
    },
    {
        "action": "log",  # 로그 기록
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 인증 봇 및 정적 제외
        "description": "[EV] Page View AVG 1m 250Req",  # 페이지 평균 트래픽 탐지
        "enabled": True,  # 룰 활성화
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],  # 방문자 기준
            "period": 60,  # 1분 기준
            "requests_per_period": 250,  # 250회 초과
            "mitigation_timeout": 600,  # 제한 유지
            "counting_expression": '(http.request.method ne "POST")',  # 페이지 요청만 집계
        },
    },
]

def api_headers():  # Cloudflare API 인증 헤더 생성 함수
    return {"Authorization": f"Bearer {token}"}  # Bearer Token 인증 방식

def get_ruleset(zone, ruleset_id):  # 특정 Ruleset 상세 조회 함수
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"  # Ruleset 조회 URL
    resp = requests.get(url, headers=api_headers())  # GET 요청
    resp.raise_for_status()  # HTTP 에러 발생 시 예외
    return resp.json().get("result", {})  # Ruleset 상세 반환

def merge_rules(existing_rules, new_rules):  # 기존 룰과 신규 룰 병합 함수
    existing_keys = {(r.get("description", ""), r.get("expression", ""), r.get("action", "")) for r in existing_rules}  # 중복 판별 키
    merged = list(existing_rules)  # 기존 룰 복사
    for rule in new_rules:  # 신규 룰 순회
        key = (rule.get("description", ""), rule.get("expression", ""), rule.get("action", ""))  # 신규 룰 키 생성
        if key in existing_keys:  # 이미 존재하면
            print(f"skip duplicate rule: {rule.get('description', '(no description)')}")  # 중복 룰 스킵 로그
            continue
        merged.append(rule)  # 신규 룰 추가
        existing_keys.add(key)  # 키 등록
    return merged  # 병합된 룰 반환

def update_ruleset(zone, ruleset, ruleset_id, merged_rules):  # Ruleset 업데이트 함수
    payload = {"name": ruleset.get("name", ""), "description": ruleset.get("description", ""), "kind": ruleset.get("kind", ""), "phase": ruleset.get("phase", ""), "rules": merged_rules}  # Cloudflare API 요청 바디
    if not APPLY_CHANGES:  # Dry-run 모드일 경우
        print(f"[DRY RUN] Would update ruleset {ruleset_id} with {len(merged_rules)} rules")  # 적용 예정 출력
        return None
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"  # Ruleset 업데이트 URL
    resp = requests.put(url, headers=api_headers(), json=payload)  # PUT 요청
    if not resp.ok:  # 실패 시
        print(f"update failed: {resp.status_code} {resp.reason}")  # 상태 코드 출력
        print(resp.text)  # 에러 본문 출력
    resp.raise_for_status()  # 에러 발생 시 예외
    return resp.json()  # API 응답 반환

# 1) List rulesets  # Zone에 존재하는 모든 Ruleset 목록 조회 시작
list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"  # Zone Ruleset 목록 조회 API URL
resp = requests.get(list_url, headers=api_headers())  # Ruleset 목록 조회 요청
resp.raise_for_status()  # HTTP 오류 발생 시 예외 처리
data = resp.json()  # JSON 응답 파싱

rows = data.get("result", [])  # Ruleset 목록 추출
if not rows:  # Ruleset이 하나도 없을 경우
    print("no rulesets found")  # 안내 메시지 출력
else:
    print("name | phase | kind")  # 출력 헤더
    print("-" * 120)  # 구분선
    for r in rows:  # 모든 Ruleset 순회
        name = r.get("name", "")  # Ruleset 이름
        phase = r.get("phase", "")  # 적용 Phase (예: http_request_firewall_custom)
        kind = r.get("kind", "")  # Ruleset 종류 (zone / account)
        print(f"{name} | {phase} | {kind}")  # Ruleset 정보 출력

# 2) WAF custom ruleset: phase == http_request_firewall_custom, kind == zone  # Custom WAF Ruleset 처리 시작
custom_ruleset = next(  # 조건에 맞는 Ruleset 하나 선택
    (r for r in rows if r.get("phase") == "http_request_firewall_custom" and r.get("kind") == "zone"),  # Zone 단위 Custom WAF Ruleset
    None,  # 없으면 None 반환
)

if not custom_ruleset:  # Custom WAF Ruleset이 없을 경우
    print("\ncustom ruleset (http_request_firewall_custom) not found.")  # 안내 메시지
else:
    cr_id = custom_ruleset["id"]  # Custom Ruleset ID
    print(f"\ncustom ruleset (http_request_firewall_custom) id: {cr_id}")  # Ruleset ID 출력
    detail = get_ruleset(zone_id, cr_id)  # Ruleset 상세 조회
    rules = detail.get("rules", [])  # 기존 Custom Rule 목록
    if not rules:  # 기존 룰이 없을 경우
        print("no custom rules found.")  # 안내 출력
    else:
        print("id | enabled | action | description | expression")  # 출력 헤더
        print("-" * 120)  # 구분선
        for rule in rules:  # 기존 Custom Rule 순회
            rid = rule.get("id", "")  # Rule ID
            enabled = rule.get("enabled", True)  # 활성화 여부
            action = rule.get("action", "")  # action (log / block / challenge 등)
            desc = rule.get("description", "")  # Rule 설명
            expr = rule.get("expression", "")  # Rule 조건식
            if len(rid) > 10:  # ID가 길 경우
                rid = rid[:5] + "..."  # 축약 출력
            if len(desc) > 60:  # 설명이 길 경우
                desc = desc[:57] + "..."  # 축약 출력
            if len(expr) > 10:  # expression 길 경우
                expr = expr[:8] + "..."  # 축약 출력
            print(f"{rid} | {enabled} | {action} | {desc} | {expr}")  # Rule 정보 출력
    if NEW_CUSTOM_RULES:  # 신규 Custom Rule이 정의돼 있으면
        merged = merge_rules(rules, NEW_CUSTOM_RULES)  # 기존 + 신규 룰 병합
        if len(merged) == len(rules):  # 병합 후 길이가 동일하면
            print("No new custom rules to add.")  # 추가할 룰 없음
        else:
            update_ruleset(zone_id, detail, cr_id, merged)  # Custom Ruleset 업데이트

# 3) Rate limit ruleset: phase == http_ratelimit, kind == zone  # Rate Limit Ruleset 처리 시작
ratelimit_ruleset = next(  # 조건에 맞는 Rate Limit Ruleset 선택
    (r for r in rows if r.get("phase") == "http_ratelimit" and r.get("kind") == "zone"),  # Zone 단위 Rate Limit
    None,  # 없으면 None
)

if not ratelimit_ruleset:  # Rate Limit Ruleset이 없을 경우
    print("\nrate limit ruleset (http_ratelimit) not found.")  # 안내 메시지
else:
    rl_id = ratelimit_ruleset["id"]  # Rate Limit Ruleset ID
    print(f"\nrate limit ruleset (http_ratelimit) id: {rl_id}")  # Ruleset ID 출력
    detail = get_ruleset(zone_id, rl_id)  # Ruleset 상세 조회
    rules = detail.get("rules", [])  # 기존 Rate Limit Rule 목록
    if not rules:  # 기존 룰이 없을 경우
        print("no rate limit rules found.")  # 안내 출력
    else:
        print("id | enabled | action | description | expression")  # 출력 헤더
        print("-" * 120)  # 구분선
        for rule in rules:  # Rate Limit Rule 순회
            rid = rule.get("id", "")  # Rule ID
            enabled = rule.get("enabled", True)  # 활성화 여부
            action = rule.get("action", "")  # action 값
            desc = rule.get("description", "")  # 설명
            expr = rule.get("expression", "")  # 조건식
            if len(rid) > 10:  # ID 길면
                rid = rid[:5] + "..."  # 축약
            if len(desc) > 60:  # 설명 길면
                desc = desc[:57] + "..."  # 축약
            if len(expr) > 10:  # expression 길면
                expr = expr[:8] + "..."  # 축약
            print(f"{rid} | {enabled} | {action} | {desc} | {expr}")  # Rule 정보 출력
    if NEW_RATELIMIT_RULES:  # 신규 Rate Limit Rule이 정의돼 있으면
        merged = merge_rules(rules, NEW_RATELIMIT_RULES)  # 기존 + 신규 룰 병합
        if len(merged) == len(rules):  # 병합 결과 동일
            print("No new rate limit rules to add.")  # 추가 없음
        else:
            update_ruleset(zone_id, detail, rl_id, merged)  # Rate Limit Ruleset 업데이트
