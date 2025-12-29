import requests

# =========================
# 인증 정보 설정
# =========================

# Cloudflare API Token (절대 외부에 노출하면 안 됨)
token = "Please insert your TOKEN"

# Cloudflare Zone ID (도메인 단위 고유 ID)
zone_id = "please insert your Zone ID"

# True  → 실제로 Cloudflare에 룰을 적용
# False → 변경 예정 내용만 출력 (Dry-run)
APPLY_CHANGES = True


# =========================
# 추가할 WAF Custom Rules
# (http_request_firewall_custom)
# =========================
NEW_CUSTOM_RULES = [
    {
        # action: log → 차단하지 않고 로그만 남김
        "action": "log",

        # Bot Management 점수가 1 (확실한 봇)
        #  - verified_bot 아님
        #  - 정적 리소스 요청 아님
        "expression": (
            '(cf.bot_management.score eq 1 '
            'and not cf.bot_management.verified_bot '
            'and not cf.bot_management.static_resource)'
        ),

        "description": "[EV] Definite bot traffic Score 1",
        "enabled": True,
    },
    {
        # Bot Management 점수 2~29 → 봇일 가능성 높음
        "action": "log",
        "expression": (
            '(cf.bot_management.score ge 2 '
            'and cf.bot_management.score le 29 '
            'and not cf.bot_management.verified_bot '
            'and not cf.bot_management.static_resource)'
        ),
        "description": "[EV] Likely bot traffic score 2 ~ 29",
        "enabled": True,
    }
]


# =========================
# 추가할 Rate Limit Rules
# (http_ratelimit)
# =========================
NEW_RATELIMIT_RULES = [
    {
        "action": "log",

        # verified bot 제외 → 일반 사용자 + 악성 봇만 대상
        "expression": '(not cf.bot_management.verified_bot)',

        "description": "[EV] Origin Error Burst 10s 60Req",
        "enabled": True,

        # Rate Limit 세부 조건
        "ratelimit": {
            # 트래픽 식별 기준
            # - Cloudflare PoP
            # - 방문자 고유 ID
            "characteristics": [
                "cf.colo.id",
                "cf.unique_visitor_id"
            ],

            # 10초 동안
            "period": 10,

            # 60 요청 초과 시 트리거
            "requests_per_period": 60,

            # 제한 발생 시 600초 동안 유지
            "mitigation_timeout": 600,

            # 카운트 대상 → 에러 응답 코드만 집계
            "counting_expression": (
                '(http.response.code in '
                '{400 401 402 403 404 405 406 407 408 409 '
                '410 411 412 413 414 415 416 417 418 422 '
                '426 500 501 502 503 504 505 507 508 510 511})'
            ),
        },
    },

    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot)',
        "description": "[EV] Origin Error AVG 1m 120Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": [
                "cf.colo.id",
                "cf.unique_visitor_id"
            ],
            "period": 60,
            "requests_per_period": 120,
            "mitigation_timeout": 600,
            "counting_expression": (
                '(http.response.code in '
                '{400 401 402 403 404 405 406 407 408 409 '
                '410 411 412 413 414 415 416 417 418 422 '
                '426 500 501 502 503 504 505 507 508 510 511})'
            ),
        },
    },

    {
        "action": "log",
        "expression": (
            '(not cf.bot_management.verified_bot '
            'and not cf.bot_management.static_resource)'
        ),
        "description": "[EV] POST Request Burst 10s 50Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": [
                "cf.colo.id",
                "cf.unique_visitor_id"
            ],
            "period": 60,
            "requests_per_period": 50,
            "mitigation_timeout": 600,

            # POST 요청만 카운트
            "counting_expression": '(http.request.method eq "POST")',
        },
    },

    {
        "action": "log",
        "expression": (
            '(not cf.bot_management.verified_bot '
            'and not cf.bot_management.static_resource)'
        ),
        "description": "[EV] POST Request AVG 1m 100Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": [
                "cf.colo.id",
                "cf.unique_visitor_id"
            ],
            "period": 60,
            "requests_per_period": 100,
            "mitigation_timeout": 600,
            "counting_expression": '(http.request.method eq "POST")',
        },
    },

    {
        "action": "log",
        "expression": (
            '(not cf.bot_management.verified_bot '
            'and not cf.bot_management.static_resource)'
        ),
        "description": "[EV] Page View Burst 10s 120Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": [
                "cf.colo.id",
                "cf.unique_visitor_id"
            ],
            "period": 10,
            "requests_per_period": 120,
            "mitigation_timeout": 600,

            # POST 제외 → 일반 페이지 조회
            "counting_expression": '(http.request.method ne "POST")',
        },
    },

    {
        "action": "log",
        "expression": (
            '(not cf.bot_management.verified_bot '
            'and not cf.bot_management.static_resource)'
        ),
        "description": "[EV] Page View AVG 1m 250Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": [
                "cf.colo.id",
                "cf.unique_visitor_id"
            ],
            "period": 60,
            "requests_per_period": 250,
            "mitigation_timeout": 600,
            "counting_expression": '(http.request.method ne "POST")',
        },
    },
]


# =========================
# 공통 API 헤더
# =========================
def api_headers():
    """
    Cloudflare API 인증 헤더 반환
    """
    return {
        "Authorization": f"Bearer {token}"
    }


# =========================
# Ruleset 상세 조회
# =========================
def get_ruleset(zone, ruleset_id):
    """
    특정 ruleset의 상세 정보 조회
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"
    resp = requests.get(url, headers=api_headers())
    resp.raise_for_status()
    return resp.json().get("result", {})


# =========================
# 기존 룰 + 신규 룰 병합
# (중복 방지)
# =========================
def merge_rules(existing_rules, new_rules):
    """
    description + expression + action 기준으로
    중복 룰을 제거하면서 병합
    """
    existing_keys = {
        (r.get("description", ""), r.get("expression", ""), r.get("action", ""))
        for r in existing_rules
    }

    merged = list(existing_rules)

    for rule in new_rules:
        key = (
            rule.get("description", ""),
            rule.get("expression", ""),
            rule.get("action", "")
        )

        if key in existing_keys:
            print(f"skip duplicate rule: {rule.get('description', '(no description)')}")
            continue

        merged.append(rule)
        existing_keys.add(key)

    return merged


# =========================
# Ruleset 업데이트
# =========================
def update_ruleset(zone, ruleset, ruleset_id, merged_rules):
    """
    병합된 룰을 Cloudflare에 반영
    """
    payload = {
        "name": ruleset.get("name", ""),
        "description": ruleset.get("description", ""),
        "kind": ruleset.get("kind", ""),
        "phase": ruleset.get("phase", ""),
        "rules": merged_rules,
    }

    if not APPLY_CHANGES:
        print(f"[DRY RUN] Would update ruleset {ruleset_id} with {len(merged_rules)} rules")
        return None

    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"
    resp = requests.put(url, headers=api_headers(), json=payload)

    if not resp.ok:
        print(f"update failed: {resp.status_code} {resp.reason}")
        print(resp.text)

    resp.raise_for_status()
    return resp.json()


# =========================
# 1) Zone 내 모든 Ruleset 조회
# =========================
list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
resp = requests.get(list_url, headers=api_headers())
resp.raise_for_status()

rows = resp.json().get("result", [])

print("name | phase | kind")
print("-" * 120)
for r in rows:
    print(f"{r.get('name')} | {r.get('phase')} | {r.get('kind')}")


# =========================
# 2) Custom WAF Ruleset 처리
# =========================
custom_ruleset = next(
    (r for r in rows
     if r.get("phase") == "http_request_firewall_custom"
     and r.get("kind") == "zone"),
    None,
)

if custom_ruleset:
    cr_id = custom_ruleset["id"]
    detail = get_ruleset(zone_id, cr_id)
    merged = merge_rules(detail.get("rules", []), NEW_CUSTOM_RULES)
    update_ruleset(zone_id, detail, cr_id, merged)


# =========================
# 3) Rate Limit Ruleset 처리
# =========================
ratelimit_ruleset = next(
    (r for r in rows
     if r.get("phase") == "http_ratelimit"
     and r.get("kind") == "zone"),
    None,
)

if ratelimit_ruleset:
    rl_id = ratelimit_ruleset["id"]
    detail = get_ruleset(zone_id, rl_id)
    merged = merge_rules(detail.get("rules", []), NEW_RATELIMIT_RULES)
    update_ruleset(zone_id, detail, rl_id, merged)
