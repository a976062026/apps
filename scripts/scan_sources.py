"""Alist 源扫描 + 白名单自动补齐（GitHub Actions 每周任务 · 并行版）

只增不改：发现白名单外新目录（含 ipa/tipa）→ 追加锚点；绝不删除/改名现有条目。
输出：apps.json（若更新）+ scan-report.md（本轮变化）+ baseline.json（下轮基线）
"""
import io
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

APPS_JSON = "apps.json"
BASELINE = "baseline.json"
REPORT = "scan-report.md"
TIMEOUT = 12
RETRY = 1
WORKERS = 10
MAX_DIRS_PER_ROOT = 250  # 单根树目录上限（超限标记 partial，防 CI 超时）


def api_list(base, path, per_page=200):
    body = json.dumps({"path": path, "password": "", "page": 1, "per_page": per_page, "refresh": False}).encode()
    req = urllib.request.Request(base + "/api/fs/list", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    last = None
    for _ in range(RETRY + 1):
        try:
            r = json.loads(urllib.request.urlopen(req, timeout=TIMEOUT).read().decode())
            if r.get("code") == 200:
                return r.get("data", {}).get("content") or []
            return []
        except Exception as e:
            last = e
    return None  # 失败（None=网络级失败，区别于空目录）


def is_ipa(name):
    return name.lower().endswith((".ipa", ".tipa"))


def bfs_tree(base, root, max_dirs=MAX_DIRS_PER_ROOT):
    """白名单树 BFS：返回 (目录集, 含包目录集, 扫描数, partial)"""
    found, ipa_dirs = set(), set()
    q = deque([root])
    scanned = 0
    partial = False
    while q:
        if scanned >= max_dirs:
            partial = True
            break
        batch = []
        while q and len(batch) < WORKERS:
            batch.append(q.popleft())
        if not batch:
            break
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            results = list(ex.map(lambda p: (p, api_list(base, p)), batch))
        for p, items in results:
            scanned += 1
            if items is None:
                continue
            for it in items:
                nm = it.get("name", "")
                if it.get("is_dir"):
                    child = p.rstrip("/") + "/" + nm
                    q.append(child)
                    found.add(child)
                elif is_ipa(nm):
                    ipa_dirs.add(p)
    return found, ipa_dirs, scanned, partial


def gap_probe(base, allowed, exclusions=None, blocked=None, disabled=None):
    """白名单缺口：每根父目录一层，发现含包的白名单外目录
    exclusions: 该源排除路径列表（管理员指定，扫描永不补）
    blocked/disabled: 全局屏蔽词/停用路径片段，命中不补"""
    exclusions = set(exclusions or [])
    blocked = set(blocked or [])
    disabled = set(disabled or [])

    def excluded(path):
        if path in exclusions or any(path.startswith(e.rstrip("/") + "/") for e in exclusions):
            return True
        segs = [x for x in path.split("/") if x]
        if any(any(b and b in seg for b in blocked) for seg in segs):
            return True
        if any(any(d and d in seg for d in disabled) for seg in segs):
            return True
        return False

    parents = sorted({r.rstrip("/").rsplit("/", 1)[0] or "/" for r in allowed})
    targets = []
    for parent in parents:
        if parent in allowed or excluded(parent):
            continue
        items = api_list(base, parent)
        if not items:
            continue
        for it in items:
            if it.get("is_dir"):
                child = parent.rstrip("/") + "/" + it.get("name", "")
                if child not in allowed and not any(a.startswith(child + "/") for a in allowed) and not excluded(child):
                    targets.append(child)
    if not targets:
        return []
    gaps = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(api_list, base, t): t for t in targets[:60]}
        for fu in as_completed(futs):
            t = futs[fu]
            items = fu.result()
            if items and any(is_ipa(x.get("name", "")) for x in items):
                gaps.append(t)
    return sorted(gaps)


def main():
    apps = json.load(open(APPS_JSON, encoding="utf-8"))
    try:
        baseline = json.load(open(BASELINE, encoding="utf-8"))
    except Exception:
        baseline = {}

    changes = []
    notes = []
    new_baseline = {}

    for src in apps.get("alist_sources", []):
        name = src.get("name", "?")
        base = src.get("baseUrl")
        pds = src.get("presetDirs") or []
        t0 = time.time()
        if not pds:
            items = api_list(base, "/")
            new_baseline[name] = {"root_entries": len(items or []), "scanned_at": time.strftime("%Y-%m-%d %H:%M")}
            print(f"[{name}] 无白名单，连通 {'OK' if items is not None else 'FAIL'}，根 {len(items or [])} 项")
            continue
        allowed = {pd.get("path") for pd in pds}

        roots = sorted(r for r in allowed if not any(r != x and r.startswith(x.rstrip("/") + "/") for x in allowed))
        total_dirs, total_ipa, total_scanned, any_partial = set(), set(), 0, False
        for root in roots:
            fd, idirs, sc, partial = bfs_tree(base, root)
            total_dirs |= fd
            total_ipa |= idirs
            total_scanned += sc
            any_partial = any_partial or partial

        prev = baseline.get(name, {})
        prev_dirs = set(prev.get("dirs", []))
        added = total_dirs - prev_dirs
        if prev_dirs and added:
            changes.append(f"**{name}**：白名单树内新增 {len(added)} 目录 → {sorted(added)[:8]}{' …' if len(added) > 8 else ''}")

        exclusions = []
        for ex in (apps.get("scan_exclusions") or []):
            if ex.get("source") in (name, src.get("id")) or ex.get("source") == "*":
                exclusions.extend(ex.get("paths") or [])
        gaps = gap_probe(base, allowed, exclusions=exclusions,
                         blocked=apps.get("blocked_keywords") or [],
                         disabled=apps.get("disabled_paths") or [])
        if gaps:
            changes.append(f"**{name}**：白名单缺口 {len(gaps)} 个（含包目录，已自动补锚点）→ {gaps[:10]}{' …' if len(gaps) > 10 else ''}")
            for g in gaps:
                src["presetDirs"].append({"path": g})

        new_baseline[name] = {
            "dirs": sorted(total_dirs),
            "ipa_dirs": len(total_ipa),
            "scanned": total_scanned,
            "partial": any_partial,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M"),
        }
        cost = int(time.time() - t0)
        note = f"[{name}] 目录 {len(total_dirs)}（含包 {len(total_ipa)}），扫描 {total_scanned} 次，{cost}s，缺口 {len(gaps)}"
        if any_partial:
            note += " | ⚠部分超限未扫完"
            notes.append(f"{name} 扫描超限（目录上限 {MAX_DIRS_PER_ROOT}），结果为部分覆盖")
        print(note)

    json.dump(new_baseline, open(BASELINE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    now = time.strftime("%Y-%m-%d %H:%M UTC")
    if changes:
        lines = [f"# 源巡检 {now}", "", "## 本轮变化", ""]
        lines += [f"- {c}" for c in changes]
        lines += ["", "apps.json 已自动补齐锚点（只增不改），Pages 发布后生效。"]
        json.dump(apps, open(APPS_JSON, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    else:
        lines = [f"# 源巡检 {now}", "", "本轮无变化，所有源白名单与实际目录一致。"]
    if notes:
        lines += ["", "## 注意", ""] + [f"- {n}" for n in notes]
    open(REPORT, "w", encoding="utf-8").write("\n".join(lines))
    print("\n" + "\n".join(lines))


if __name__ == "__main__":
    main()
