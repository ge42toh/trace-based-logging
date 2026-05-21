import argparse, csv, os, re, sys, yaml
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
LOOP_RE = re.compile(r'^(.+?)_(loop\d+)_(\d+)$')


@dataclass
class Rules:
    excluded: set = field(default_factory=set)
    included: set = field(default_factory=set)
    loops: dict = field(default_factory=dict)  # eid -> {mode, iteration, tasks, name}
    subscriptions: set = field(default_factory=set)

@dataclass
class Event:
    activity: str
    lifecycle: str
    timestamp: str
    instance: str
    raw: dict

@dataclass
class Trace:
    path: str
    uuid: str
    name: str
    events: list
    header: dict

@dataclass
class Result:
    name: str
    passed: bool
    summary: str = ""
    details: list = field(default_factory=list)


def _tag(t):
    return t.split('}', 1)[-1] if '}' in t else t


def parse_xml(path):
    root = ET.parse(path).getroot()
    rules = Rules()
    desc = None
    for el in root.iter():
        if _tag(el.tag) == 'description':
            for ch in el:
                if _tag(ch.tag) == 'description':
                    desc = ch
                    break
            if desc:
                break
    if desc is None:
        for el in root.iter():
            if _tag(el.tag) == 'description':
                desc = el
                break
    if desc:
        for el in desc.iter():
            if _tag(el.tag) not in ('call', 'subprocess'):
                continue
            tid = el.get('id')
            if not tid:
                continue
            for ch in el.iter():
                tag, val = _tag(ch.tag), (ch.text or '').strip().lower()
                if tag == '_exclude' and val in ('on', 'true'):
                    rules.excluded.add(tid)
                if tag == '_include' and val in ('on', 'true'):
                    rules.included.add(tid)
        n = 1
        for el in desc.iter():
            if _tag(el.tag) != 'loop':
                continue
            eid = el.get('eid') or el.get('id')
            if not eid:
                continue
            iteration = any(
                _tag(ch.tag) == '_iteration' and (ch.text or '').strip().lower() in ('on', 'true')
                for ch in el.iter())
            tasks = {ch.get('id') for ch in el.iter()
                     if _tag(ch.tag) in ('call', 'subprocess', 'manipulate') and ch.get('id')}
            rules.loops[eid] = {
                'mode': el.get('mode', 'pre_test'),
                'iteration': iteration,
                'tasks': tasks,
                'name': f'loop{n}',
            }
            n += 1
    for el in root.iter():
        if _tag(el.tag) != 'subscription' or '9379' not in el.get('url', ''):
            continue
        for topic in el:
            if _tag(topic.tag) != 'topic':
                continue
            tid = topic.get('id', '')
            for ev in topic:
                if _tag(ev.tag) == 'event' and ev.text:
                    rules.subscriptions.add((tid, ev.text.strip()))
    return rules


def parse_trace(path):
    try:
        with open(path, encoding='utf-8') as f:
            docs = [d for d in yaml.safe_load_all(f.read()) if d]
    except Exception:
        return None
    if not docs:
        return None
    first = docs[0]
    header, event_docs = (first, docs[1:]) if isinstance(first, dict) and 'log' in first else ({}, docs)
    log = header.get('log', header)
    meta = log.get('trace', {}) if isinstance(log, dict) else {}
    uuid, name = str(meta.get('cpee:instance', '')), str(meta.get('cpee:name', ''))
    events = []
    for doc in event_docs:
        if not isinstance(doc, dict):
            continue
        evt = doc.get('event')
        if not isinstance(evt, dict):
            continue
        aid = str(evt.get('id:id', 'external'))
        if aid == 'ex-ante':
            aid = 'external'
        events.append(Event(aid, str(evt.get('cpee:lifecycle:transition', '')),
                            str(evt.get('time:timestamp', '')), str(evt.get('cpee:instance', uuid)), evt))
    if not uuid and events:
        uuid = events[0].instance
    return Trace(path, uuid, name, events, header)


def load_traces(folder):
    out = {}
    if not os.path.isdir(folder):
        return out
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith('.yaml'):
            continue
        tf = parse_trace(os.path.join(folder, fn))
        if tf:
            k = fn.replace('.xes.yaml', '').replace('.yaml', '')
            out[k[6:] if k.startswith('trace_') else k] = tf
    return out


def parse_key(key):
    m = LOOP_RE.match(key)
    return (m.group(1), m.group(2), int(m.group(3))) if m else (key, None, None)


def _uuids(v):
    if isinstance(v, str):
        return set(UUID_RE.findall(v))
    if isinstance(v, list):
        return set().union(*(_uuids(x) for x in v))
    if isinstance(v, dict):
        return set().union(*(_uuids(x) for x in v.values()))
    return set()


def detect_links(traces):
    known = {tf.uuid for tf in traces.values() if tf.uuid} | set(traces)
    links = {}
    for tf in traces.values():
        p = tf.uuid
        for evt in tf.events:
            if evt.lifecycle != 'activity/receiving':
                continue
            data = evt.raw.get('raw', evt.raw.get('data', []))
            for uid in _uuids(data):
                if uid != p and uid in known and uid not in links:
                    links[uid] = (p, evt.activity)
    return links


def _is_act(lc):
    return lc.startswith(('activity/', 'task/'))


def check_filtering(rules, orig, alt):
    r = Result("Event Exclusion", True)
    if not rules.excluded:
        r.summary = "No exclusion rules defined."
        return r
    for tid in sorted(rules.excluded):
        found = [e for tf in alt.values() for e in tf.events if e.activity == tid and _is_act(e.lifecycle)]
        if found:
            r.passed = False
            r.details.append(f"[FAIL] '{tid}' found {len(found)}x")
        else:
            r.details.append(f"[OK]   '{tid}' excluded")
    r.summary = f"{len(rules.excluded)} rule(s), {sum(1 for d in r.details if '[OK]' in d)} ok."
    return r


def check_subprocess(rules, orig, alt):
    r = Result("Subprocess Integration", True)
    if not rules.included:
        r.summary = "No inclusion rules defined."
        return r
    links = detect_links(orig)
    if not links:
        r.summary = "No subprocess links in original traces."
        return r
    checked = 0
    for child, (parent, aid) in links.items():
        if aid not in rules.included:
            continue
        checked += 1
        bad = any(parse_key(k)[0] == child and parse_key(k)[1] is None for k in alt)
        r.details.append(f"[{'FAIL' if bad else 'OK'}] Child '{child}'")
        if bad:
            r.passed = False
    if not checked:
        r.summary = "No _include subprocess executions."
        return r
    r.summary = f"{sum(1 for d in r.details if '[OK]' in d)}/{checked} merged."
    return r


def check_loops(rules, orig, alt):
    r = Result("Loop Unrolling", True)
    active = {e: L for e, L in rules.loops.items() if L['iteration']}
    if not active:
        r.summary = "No per-iteration loops."
        return r
    o_lc = {e.lifecycle for tf in orig.values() for e in tf.events}
    a_lc = {e.lifecycle for tf in alt.values() for e in tf.events}
    common = o_lc & a_lc

    def count_loop_ev(tf, tasks):
        return sum(1 for e in tf.events if e.activity in tasks and e.lifecycle in common and _is_act(e.lifecycle))

    for loop in active.values():
        r.details.append(f"Loop '{loop['name']}' tasks={sorted(loop['tasks'])}")
        for okey, otf in orig.items():
            ou = otf.uuid or okey
            oc = count_loop_ev(otf, loop['tasks'])
            if not oc:
                continue
            splits = []
            for ak, atf in alt.items():
                base, lname, itr = parse_key(ak)
                if base == ou and lname == loop['name'] and itr is not None:
                    splits.append((itr, count_loop_ev(atf, loop['tasks'])))
            splits.sort()
            tot = sum(c for _, c in splits)
            if not splits:
                r.passed = False
                r.details.append(f"  [FAIL] No split files '{ou}'")
            elif tot != oc:
                r.passed = False
                r.details.append(f"  [FAIL] split {tot} != orig {oc}")
            else:
                r.details.append(f"  [OK] {len(splits)} iter, {tot} ev")

    r.summary = f"{len(active)} loop(s), {sum(1 for d in r.details if '[OK]' in d)} checks ok."
    return r


def check_completeness(rules, orig, alt):
    r = Result("Completeness", True)
    o_lc = {e.lifecycle for tf in orig.values() for e in tf.events}
    a_lc = {e.lifecycle for tf in alt.values() for e in tf.events}
    common, alt_only = o_lc & a_lc, a_lc - o_lc
    if not common:
        r.passed = False
        r.summary = "No overlapping event types."
        return r

    merged = {c: p for c, (p, aid) in detect_links(orig).items() if aid in rules.included}
    first_ts = {}
    for ak, atf in alt.items():
        b = parse_key(ak)[0]
        for ev in atf.events:
            if ev.timestamp and (b not in first_ts or ev.timestamp < first_ts[b]):
                first_ts[b] = ev.timestamp

    expected, skipped = defaultdict(int), 0
    for okey, otf in orig.items():
        ouuid = otf.uuid or okey
        tgt = merged.get(ouuid, ouuid)
        cut = first_ts.get(tgt, '')
        for ev in otf.events:
            if ev.lifecycle not in common:
                continue
            if ev.activity in rules.excluded and _is_act(ev.lifecycle):
                continue
            if cut and ev.timestamp and ev.timestamp < cut:
                skipped += 1
                continue
            expected[(tgt, ev.activity, ev.lifecycle)] += 1

    actual = defaultdict(int)
    for ak, atf in alt.items():
        b = parse_key(ak)[0]
        for ev in atf.events:
            if ev.lifecycle in common:
                actual[(b, ev.activity, ev.lifecycle)] += 1

    keys = set(expected) | set(actual)
    matched, missing, extra = 0, [], []
    for k in sorted(keys):
        exp, act = expected.get(k, 0), actual.get(k, 0)
        if exp == act:
            matched += 1
        elif act < exp:
            missing.append((k, exp, act))
            r.passed = False
        else:
            extra.append((k, exp, act))

    r.details.append(f"Types: {', '.join(sorted(common))}")
    if skipped:
        r.details.append(f"Skipped {skipped} pre-subscription event(s).")
    r.details.append(f"Groups matched: {matched}/{len(keys)}")
    if missing:
        r.details.append(f"Missing {len(missing)}:")
        for (uid, aid, lc), exp, act in missing[:20]:
            r.details.append(f"  {uid} | {aid} | {lc} | exp={exp} act={act}")
    if extra:
        r.details.append(f"Extra {len(extra)}:")
        for (uid, aid, lc), exp, act in extra[:20]:
            r.details.append(f"  {uid} | {aid} | {lc} | exp={exp} act={act}")
    if alt_only:
        r.details.append(f"+{sum(1 for tf in alt.values() for e in tf.events if e.lifecycle in alt_only)} alt-only type line(s) ({', '.join(sorted(alt_only))}).")

    total_exp, total_act = sum(expected.values()), sum(actual.values())
    r.summary = (
        f"Expected events (total): {total_exp}, Actual events (total): {total_act}, "
        f"Event groups matched: {matched}/{len(keys)}, "
        f"Missing groups: {len(missing)}, Extra groups: {len(extra)}"
    )
    if skipped:
        r.summary += f", Pre-subscription skipped: {skipped}"
    return r


def write_csv(results, path):
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Check', 'Status', 'Summary'])
        for r in results:
            w.writerow([r.name, 'PASS' if r.passed else 'FAIL', r.summary])
            for line in r.details:
                w.writerow(['', '', line.strip()])


def write_pdf(results, path, xml_path='', orig_dir='', alt_dir=''):
    from fpdf import FPDF
    from fpdf.enums import WrapMode

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=28)
    pdf.set_margins(18, 18, 18)
    pdf.add_page()
    usable = pdf.w - pdf.l_margin - pdf.r_margin
    line = 6

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 9, "Evaluation Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(usable, line, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    if xml_path:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(usable, line, f"Model: {os.path.basename(xml_path)}", wrapmode=WrapMode.CHAR)
    if orig_dir:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(usable, line, f"Original logs: {orig_dir}", wrapmode=WrapMode.CHAR)
    if alt_dir:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(usable, line, f"Alternative logs: {alt_dir}", wrapmode=WrapMode.CHAR)
    pdf.ln(3)

    ok = all(r.passed for r in results)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*(0, 128, 0) if ok else (200, 0, 0))
    pdf.cell(0, 8, f"Verdict: {'PASS' if ok else 'FAIL'}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    for r in results:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(*(220, 255, 220) if r.passed else (255, 220, 220))
        pdf.cell(0, 7, f"{r.name} [{'PASS' if r.passed else 'FAIL'}]", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(usable, line, r.summary, wrapmode=WrapMode.CHAR)
        pdf.ln(1)
        # Detail lines: Times (serif) vs Helvetica summary — both standard PDF fonts
        pdf.set_font("Times", "", 10)
        for line_txt in r.details:
            s = line_txt.encode("latin-1", "replace").decode("latin-1").strip()
            if not s:
                pdf.ln(3)
                continue
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(usable, line, s, wrapmode=WrapMode.CHAR)
        pdf.ln(2)

    pdf.output(path)


def print_results(results):
    for r in results:
        tag = "\033[92mPASS\033[0m" if r.passed else "\033[91mFAIL\033[0m"
        print(f"\n{'='*50}\n  {r.name}  [{tag}]\n{'='*50}\n  {r.summary}")
        for d in r.details:
            print(f"    {d}")


def evaluate_once(rules, orig, alt, xml_path, orig_label, alt_label, out_dir, no_csv, no_pdf):
    os.makedirs(out_dir, exist_ok=True)
    results = [check_filtering(rules, orig, alt), check_subprocess(rules, orig, alt),
               check_loops(rules, orig, alt), check_completeness(rules, orig, alt)]
    print_results(results)
    overall = all(r.passed for r in results)
    tag = "\033[92mPASS\033[0m" if overall else "\033[91mFAIL\033[0m"
    print(f"\n{'='*50}\n  VERDICT: {tag}\n{'='*50}")
    if not no_csv:
        p = os.path.join(out_dir, "evaluation_report.csv")
        write_csv(results, p)
        print(f"\n  CSV: {p}")
    if not no_pdf:
        p = os.path.join(out_dir, "evaluation_report.pdf")
        write_pdf(results, p, xml_path, orig_label, alt_label)
        print(f"  PDF: {p}")
    return overall, results


def print_model_rules(rules):
    print("\nParsing XML model ...")
    print(f"  Excluded: {sorted(rules.excluded) or '(none)'}")
    print(f"  Included: {sorted(rules.included) or '(none)'}")
    print(f"  Loops: {len(rules.loops)}")
    for eid, li in rules.loops.items():
        print(f"    {li['name']} eid={eid} mode={li['mode']} iter={'on' if li['iteration'] else 'off'} tasks={sorted(li['tasks'])}")
    print(f"  Subscriptions: {len(rules.subscriptions)} type(s)")


def main(argv=None):
    p = argparse.ArgumentParser(description="Compare ex-post vs logger trace folders.")
    p.add_argument("--xml", required=True)
    p.add_argument("--original-logs", required=True, dest="orig")
    p.add_argument("--alternative-logs", required=True, dest="alt")
    p.add_argument("--output-dir", default="eval_results", dest="out")
    p.add_argument("--no-csv", action="store_true")
    p.add_argument("--no-pdf", action="store_true")
    args = p.parse_args(argv)
    if not os.path.isfile(args.xml):
        print(f"Error: XML not found: {args.xml}", file=sys.stderr)
        return 1
    if not os.path.isdir(args.orig):
        print(f"Error: not a directory: {args.orig}", file=sys.stderr)
        return 1
    if not os.path.isdir(args.alt):
        print(f"Error: not a directory: {args.alt}", file=sys.stderr)
        return 1
    rules = parse_xml(args.xml)
    print_model_rules(rules)
    os.makedirs(args.out, exist_ok=True)
    otr, atr = load_traces(args.orig), load_traces(args.alt)
    print(f"\nTraces: original {len(otr)} file(s), alternative {len(atr)} file(s)")
    overall, _ = evaluate_once(rules, otr, atr, args.xml, args.orig, args.alt, args.out, args.no_csv, args.no_pdf)
    print()
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
