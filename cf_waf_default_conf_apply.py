import requests

# WARNING: keep tokens safe.
token = "Please insert your TOKEN"
zone_id = "please insert your Zone ID"  # Cloudflare Zone ID

# Set to True to apply changes. When False, the script prints what would change.
APPLY_CHANGES = True

# Add rules here. Leave the lists empty to skip.
NEW_CUSTOM_RULES = [
    {
        "action": "log",
        "expression": '(cf.bot_management.score eq 1 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',
        "description": "[EV] Definite bot traffic Score 1",
        "enabled": True,
    },
    {
        "action": "log",
        "expression": '(cf.bot_management.score ge 2 and cf.bot_management.score le 29 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',
        "description": "[EV] Likely bot traffic score 2 ~ 29",
        "enabled": True,
    }
]

NEW_RATELIMIT_RULES = [
    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot)',  # 요청 조건만
        "description": "[EV] Origin Error Burst 10s 60Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],
            "period": 10,
            "requests_per_period": 60,
            "mitigation_timeout": 600,
            "counting_expression": '(http.response.code in {400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 422 426 500 501 502 503 504 505 507 508 510 511})',
        },
    },
    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot)',  # 요청 조건만
        "description": "[EV] Origin Error AVG 1m 120Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],
            "period": 60,
            "requests_per_period": 120,
            "mitigation_timeout": 600,
            "counting_expression": '(http.response.code in {400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 422 426 500 501 502 503 504 505 507 508 510 511})',
        },
    },
    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 요청 조건만
        "description": "[EV] POST Request Burst 10s 50Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],
            "period": 60,
            "requests_per_period": 50,
            "mitigation_timeout": 600,
            "counting_expression": '(http.request.method eq "POST")',
        },
    },
    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 요청 조건만
        "description": "[EV] POST Request AVG 1m 100Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],
            "period": 60,
            "requests_per_period": 100,
            "mitigation_timeout": 600,
            "counting_expression": '(http.request.method eq "POST")',
        },
    },
    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 요청 조건만
        "description": "[EV] Page View Burst 10s 120Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],
            "period": 10,
            "requests_per_period": 120,
            "mitigation_timeout": 600,
            "counting_expression": '(http.request.method ne "POST")',
        },
    },
    {
        "action": "log",
        "expression": '(not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',  # 요청 조건만
        "description": "[EV] Page View AVG 1m 250Req",
        "enabled": True,
        "ratelimit": {
            "characteristics": ["cf.colo.id", "cf.unique_visitor_id"],
            "period": 60,
            "requests_per_period": 250,
            "mitigation_timeout": 600,
            "counting_expression": '(http.request.method ne "POST")',
        },
    },
]



def api_headers():
    return {"Authorization": f"Bearer {token}"}


def get_ruleset(zone, ruleset_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/{ruleset_id}"
    resp = requests.get(url, headers=api_headers())
    resp.raise_for_status()
    return resp.json().get("result", {})


def merge_rules(existing_rules, new_rules):
    existing_keys = {
        (r.get("description", ""), r.get("expression", ""), r.get("action", ""))
        for r in existing_rules
    }
    merged = list(existing_rules)
    for rule in new_rules:
        key = (rule.get("description", ""), rule.get("expression", ""), rule.get("action", ""))
        if key in existing_keys:
            print(f"skip duplicate rule: {rule.get('description', '(no description)')}")
            continue
        merged.append(rule)
        existing_keys.add(key)
    return merged


def update_ruleset(zone, ruleset, ruleset_id, merged_rules):
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




# 1) List rulesets
list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
resp = requests.get(list_url, headers=api_headers())
resp.raise_for_status()
data = resp.json()

rows = data.get("result", [])
if not rows:
    print("no rulesets found")
else:
    print("name | phase | kind")
    print("-" * 120)
    for r in rows:
        name = r.get("name", "")
        phase = r.get("phase", "")
        kind = r.get("kind", "")
        print(f"{name} | {phase} | {kind}")

# 2) WAF custom ruleset: phase == http_request_firewall_custom, kind == zone
custom_ruleset = next(
    (r for r in rows if r.get("phase") == "http_request_firewall_custom" and r.get("kind") == "zone"),
    None,
)

if not custom_ruleset:
    print("\ncustom ruleset (http_request_firewall_custom) not found.")
else:
    cr_id = custom_ruleset["id"]
    print(f"\ncustom ruleset (http_request_firewall_custom) id: {cr_id}")
    detail = get_ruleset(zone_id, cr_id)
    rules = detail.get("rules", [])
    if not rules:
        print("no custom rules found.")
    else:
        print("id | enabled | action | description | expression")
        print("-" * 120)
        for rule in rules:
            rid = rule.get("id", "")
            enabled = rule.get("enabled", True)
            action = rule.get("action", "")
            desc = rule.get("description", "")
            expr = rule.get("expression", "")
            if len(rid) > 10:
                rid = rid[:5] + "..."
            if len(desc) > 60:
                desc = desc[:57] + "..."
            if len(expr) > 10:
                expr = expr[:8] + "..."
            print(f"{rid} | {enabled} | {action} | {desc} | {expr}")
    if NEW_CUSTOM_RULES:
        merged = merge_rules(rules, NEW_CUSTOM_RULES)
        if len(merged) == len(rules):
            print("No new custom rules to add.")
        else:
            update_ruleset(zone_id, detail, cr_id, merged)

# 3) Rate limit ruleset: phase == http_ratelimit, kind == zone
ratelimit_ruleset = next(
    (r for r in rows if r.get("phase") == "http_ratelimit" and r.get("kind") == "zone"),
    None,
)

if not ratelimit_ruleset:
    print("\nrate limit ruleset (http_ratelimit) not found.")
else:
    rl_id = ratelimit_ruleset["id"]
    print(f"\nrate limit ruleset (http_ratelimit) id: {rl_id}")
    detail = get_ruleset(zone_id, rl_id)
    rules = detail.get("rules", [])
    if not rules:
        print("no rate limit rules found.")
    else:
        print("id | enabled | action | description | expression")
        print("-" * 120)
        for rule in rules:
            rid = rule.get("id", "")
            enabled = rule.get("enabled", True)
            action = rule.get("action", "")
            desc = rule.get("description", "")
            expr = rule.get("expression", "")
            if len(rid) > 10:
                rid = rid[:5] + "..."
            if len(desc) > 60:
                desc = desc[:57] + "..."
            if len(expr) > 10:
                expr = expr[:8] + "..."
            print(f"{rid} | {enabled} | {action} | {desc} | {expr}")
    if NEW_RATELIMIT_RULES:
        merged = merge_rules(rules, NEW_RATELIMIT_RULES)
        if len(merged) == len(rules):
            print("No new rate limit rules to add.")
        else:
            update_ruleset(zone_id, detail, rl_id, merged)
