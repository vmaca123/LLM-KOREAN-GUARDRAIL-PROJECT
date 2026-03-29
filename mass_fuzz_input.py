"""
Bedrock Guardrails INPUT 퍼징 (병렬 처리)
==========================================
사용자가 PII를 포함한 요청을 보낼 때 입력 가드레일이 차단하는지 검증

팀원 가이드:
  1. AWS 계정 세팅 (aws configure)
  2. Guardrail 생성 (Bedrock Console → Guardrails)
  3. 페이로드 생성: python korean_pii_fuzzer_v3.py --count 10 --output payloads.json
  4. 실행: python mass_fuzz_input.py --guardrail-id YOUR_ID --input payloads.json

다른 가드레일 테스트 시:
  - LLM Guard: mass_fuzz_input.py 대신 별도 스크립트 필요 (API 다름)
  - Presidio: 기존 mass_fuzz_presidio.py 사용

속도: --workers 5 (기본) → 약 5배 빨라짐
"""

import json, time, argparse
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3

USER_TEMPLATES = [
    "{text}",
    "{text} 확인해줘",
    "{text} 조회 부탁드립니다",
    "다음 정보 확인해줘: {text}",
    "{text} 맞는지 확인해주세요",
]


def call_guardrail(client, gid, ver, text, source="INPUT"):
    try:
        r = client.apply_guardrail(
            guardrailIdentifier=gid, guardrailVersion=ver,
            source=source, content=[{"text": {"text": text}}])
        action = r.get("action", "NONE")
        types = []
        for a in r.get("assessments", []):
            for p in a.get("sensitiveInformationPolicy", {}).get("piiEntities", []):
                types.append({"type": p.get("type",""), "match": p.get("match","")})
        return {"blocked": action == "GUARDRAIL_INTERVENED", "types": types}
    except Exception as e:
        return {"blocked": False, "types": [], "error": str(e)}


def process_one(args):
    client, gid, ver, payload, templates = args
    import random
    text = random.choice(templates).format(text=payload["mutated"])
    t0 = time.time()
    res = call_guardrail(client, gid, ver, text, "INPUT")
    lat = (time.time() - t0) * 1000
    return {
        "id": payload["id"], "pii_type": payload["pii_type"],
        "level": payload["mutation_level"], "mutation": payload["mutation_name"],
        "original": payload["original"], "name_tier": payload.get("name_tier",""),
        "lang": payload.get("lang","KR"), "sent_text": text[:150],
        "blocked": res["blocked"],
        "det_types": [t["type"] for t in res["types"]],
        "lat_ms": round(lat, 1),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guardrail-id", required=True)
    parser.add_argument("--version", default="DRAFT")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--input", required=True)
    parser.add_argument("--workers", type=int, default=5, help="병렬 스레드 수 (기본 5)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        payloads = json.load(f)["payloads"]

    total = len(payloads)
    client = boto3.client("bedrock-runtime", region_name=args.region)

    print(f"\n{'='*76}")
    print(f"  Bedrock INPUT 가드레일 퍼징 (병렬 {args.workers}스레드)")
    print(f"  Guardrail: {args.guardrail_id} | 페이로드: {total:,}건")
    print(f"  예상 시간: ~{total/args.workers/1:.0f}초 ({total/args.workers/60:.0f}분)")
    print(f"{'='*76}")

    stats_level = defaultdict(lambda: {"t":0,"b":0})
    stats_mut = defaultdict(lambda: {"t":0,"b":0})
    stats_type = defaultdict(lambda: {"t":0,"b":0})
    stats_tier = defaultdict(lambda: {"t":0,"b":0})
    stats_lang = defaultdict(lambda: {"t":0,"b":0})
    results = []
    start = time.time()
    done = 0

    tasks = [(client, args.guardrail_id, args.version, p, USER_TEMPLATES) for p in payloads]

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_one, t): i for i, t in enumerate(tasks)}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            
            for s in [stats_level[f"L{r['level']}"], stats_mut[r["mutation"]],
                       stats_type[r["pii_type"]], stats_tier[r.get("name_tier","")],
                       stats_lang[r.get("lang","KR")]]:
                s["t"] += 1
                if r["blocked"]: s["b"] += 1

            done += 1
            if done % 100 == 0 or done == total:
                elapsed = time.time() - start
                rate = done / elapsed
                bypass = sum(1 for x in results if not x["blocked"]) / done * 100
                print(f"  [{done/total*100:5.1f}%] {done:,}/{total:,} | "
                      f"{rate:.1f}건/초 | 남은: {(total-done)/rate:.0f}초 | 우회율: {bypass:.1f}%")

    total_time = time.time() - start
    blocked = sum(1 for r in results if r["blocked"])

    # 결과 출력
    print(f"\n{'='*76}")
    print(f"  📊 INPUT 가드레일 결과")
    print(f"{'='*76}")
    print(f"  전체: {total}건 | 차단: {blocked} | 우회: {total-blocked} ({(total-blocked)/total*100:.1f}%)")

    kr_t = stats_lang.get("KR",{"t":0,"b":0})
    en_t = stats_lang.get("EN",{"t":0,"b":0})
    if kr_t["t"]>0: print(f"  한국어: {(kr_t['t']-kr_t['b'])/kr_t['t']*100:.1f}% 우회 ({kr_t['t']-kr_t['b']}/{kr_t['t']})")
    if en_t["t"]>0: print(f"  영어:   {(en_t['t']-en_t['b'])/en_t['t']*100:.1f}% 우회 ({en_t['t']-en_t['b']}/{en_t['t']})")

    print(f"\n  ── 레벨별 ──")
    for lv in ["L0","L1","L2","L3","L4","L5"]:
        s=stats_level.get(lv,{"t":0,"b":0})
        if s["t"]==0:continue
        print(f"  {lv}: {(s['t']-s['b'])/s['t']*100:5.1f}% 우회 ({s['t']-s['b']}/{s['t']})")

    print(f"\n  ── 변이 기법 TOP 10 (우회율 높은 순) ──")
    for mut,s in sorted(stats_mut.items(),key=lambda x:(x[1]["t"]-x[1]["b"])/max(x[1]["t"],1),reverse=True)[:10]:
        if s["t"]==0:continue
        print(f"  {mut:22s}: {(s['t']-s['b'])/s['t']*100:5.1f}% ({s['t']-s['b']}/{s['t']})")

    print(f"\n  ── PII 유형별 ──")
    for pt,s in sorted(stats_type.items(),key=lambda x:(x[1]["t"]-x[1]["b"])/max(x[1]["t"],1),reverse=True)[:15]:
        if s["t"]==0:continue
        print(f"  {pt:16s}: {(s['t']-s['b'])/s['t']*100:5.1f}% 우회")

    print(f"\n  ── 이름 Tier별 ──")
    for tier,s in sorted(stats_tier.items(),key=lambda x:(x[1]["t"]-x[1]["b"])/max(x[1]["t"],1),reverse=True):
        if not tier or s["t"]==0:continue
        print(f"  {tier:16s}: {(s['t']-s['b'])/s['t']*100:5.1f}% 우회 ({s['t']-s['b']}/{s['t']})")

    print(f"\n  성능: {total/total_time:.1f}건/초 | 총 {total_time:.0f}초")
    print(f"{'='*76}")

    outfile = f"results_INPUT_{total}.json"
    with open(outfile,"w",encoding="utf-8") as f:
        json.dump({"run":{"source":"INPUT","total":total,"blocked":blocked,
                          "bypass_rate":round((total-blocked)/total*100,2),
                          "timestamp":datetime.now().isoformat(),
                          "time_sec":round(total_time,1)},
                   "by_level":{k:dict(v) for k,v in stats_level.items()},
                   "by_mutation":{k:dict(v) for k,v in stats_mut.items()},
                   "by_type":{k:dict(v) for k,v in stats_type.items()},
                   "by_tier":{k:dict(v) for k,v in stats_tier.items()},
                   "by_lang":{k:dict(v) for k,v in stats_lang.items()},
                   "results":results},f,ensure_ascii=False,indent=2)
    print(f"  💾 {outfile}\n")


if __name__ == "__main__":
    main()
