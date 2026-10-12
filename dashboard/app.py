"""Streamlit dashboard: a thin analyst UI over the FastAPI service.

    .venv/bin/streamlit run dashboard/app.py

The API must be running (see README). Point at another host with SOC_API.
"""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

import client  # noqa: E402

st.set_page_config(page_title="SOC Log Analyzer", page_icon="🛡️", layout="wide")


# --- sidebar: where the API is and whether it can answer --------------------

with st.sidebar:
    st.header("Engine")
    api = st.text_input("API URL", client.DEFAULT_API)
    h = client.health(api)
    status = h["status"]
    if status == "ready":
        st.success(f"Ready · `{h['configured_model']}`")
        st.caption(f"Prompt `{h['prompt_version']}`")
    elif status == "model_missing":
        st.warning(f"Ollama is up but `{h['configured_model']}` is not pulled. Rules still work.")
    elif status == "ollama_down":
        st.warning("API is up, Ollama is not. Rules still work; full analysis will fail.")
    elif status == "api_down":
        st.error(f"No API at {api}. Start it with `uvicorn app.main:app`.")
    else:
        st.error(f"API error: {h.get('detail')}")
    if st.button("Re-check"):
        st.rerun()

    st.divider()
    st.caption(
        "**Rules only** runs 8 deterministic rules in under a millisecond. "
        "**Full analysis** runs the rules, then the model (~15s), and lets the "
        "rules raise the model's severity but never lower it."
    )


# --- input -----------------------------------------------------------------

st.title("🛡️ Security Log Analyzer")

corpus = client.samples()
by_title = {s.title: s for s in corpus}

origin = st.radio("Log source", ["Corpus sample", "Upload a file", "Paste text"], horizontal=True)
sample = None
log_text, source_hint = "", None

if origin == "Corpus sample":
    pick = st.selectbox(
        "Sample",
        list(by_title),
        help="samples/ is the dev set the rules were written against; holdout/ is not.",
    )
    sample = by_title[pick]
    log_text, source_hint = sample.path.read_text(), sample.name
elif origin == "Upload a file":
    upload = st.file_uploader("Log file", type=None)
    if upload is not None:
        log_text = upload.getvalue().decode("utf-8", errors="replace")
        source_hint = upload.name
else:
    log_text = st.text_area("Log text", height=200, placeholder="Paste raw log lines here")

if log_text and origin != "Paste text":
    st.code(log_text, language="log", line_numbers=True)
source_hint = st.text_input("Source hint (optional)", source_hint or "",
                            help="Tells the model what kind of log this is, e.g. auth.log") or None

left, right, _ = st.columns([1, 1, 4])
run_rules = left.button("Rules only", disabled=not log_text.strip(), use_container_width=True)
run_full = right.button("Full analysis", type="primary", use_container_width=True,
                        disabled=not log_text.strip() or status not in ("ready",))

# Results survive reruns (e.g. expanding a panel) but not a change of input.
key = (log_text, source_hint)
if st.session_state.get("key") != key:
    st.session_state.pop("result", None)
    st.session_state["key"] = key

try:
    if run_rules:
        st.session_state["result"] = ("rules", client.prefilter(log_text, api))
    elif run_full:
        with st.spinner("Rules, then the model…"):
            st.session_state["result"] = ("full", client.analyze(log_text, source_hint, api))
except client.ApiError as exc:
    st.error(str(exc))

if "result" not in st.session_state:
    st.stop()

mode, result = st.session_state["result"]
st.divider()


# --- rendering -------------------------------------------------------------

def badge(severity: str) -> None:
    st.badge(severity.upper(), color=client.SEVERITY_COLOR.get(severity, "gray"))


def render_rules(report: dict) -> None:
    st.subheader("Rule layer")
    st.caption(f"{report['events_parsed']} events parsed · floor **{report['severity_floor']}**")
    if report["clean"]:
        st.info("No rule fired. The rules cover 8 specific patterns, so silence here "
                "is not evidence the log is safe.")
        return
    for s in report["signals"]:
        with st.expander(f"{s['rule_id']} · {s['name']} · {s['severity'].upper()}", expanded=True):
            st.write(s["detail"])
            if s.get("technique_id"):
                st.markdown(f"[{s['technique_id']}]({client.attack_url(s['technique_id'])})")
            st.code("\n".join(s["lines"]), language="log")


def render_label(verdict: str, severity: str, technique: str | None) -> None:
    if sample is None or sample.label is None:
        return
    label = sample.label
    marks = client.against_label(label, verdict, severity, technique)
    st.subheader("Against the label")
    expected_t = ", ".join(label["mitre_any_of"]) or "none"
    rows = [
        ("verdict", label["verdict"], verdict, marks["verdict"]),
        ("severity", label["severity"], severity, marks["severity"]),
        ("technique", expected_t, technique or "none", marks["technique"]),
    ]
    st.table([{"field": f, "expected": e, "got": g, "": "✅" if ok else "❌"} for f, e, g, ok in rows])
    if label.get("note"):
        st.caption(label["note"])
    if sample.dataset == "samples":
        st.caption("Dev set: the detector was written against this file, so a match "
                   "here measures agreement, not accuracy.")


if mode == "rules":
    report = result
    floor = report["severity_floor"]
    worst = max(report["signals"], key=lambda s: client.SEVERITY_ORDER[s["severity"]], default=None)
    technique = worst["technique_id"] if worst else None
    verdict = client.VERDICT_FOR_FLOOR[floor]
    c1, c2 = st.columns(2)
    # Silence from 8 narrow rules is not a benign verdict, whatever evaluate.py scores it as.
    c1.metric("Verdict (rules)", "— no rule fired" if report["clean"]
              else f"{client.VERDICT_ICON[verdict]} {verdict}")
    with c2:
        st.caption("Severity floor")
        badge(floor)
    main, side = st.columns([3, 2])
    with main:
        render_rules(report)
    with side:
        render_label(verdict, floor, technique)
    st.stop()

a, report = result["analysis"], result["prefilter"]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Verdict", f"{client.VERDICT_ICON[a['verdict']]} {a['verdict']}")
with c2:
    st.caption("Severity")
    badge(a["severity"])
c3.metric("Confidence", f"{a['confidence']:.0%}")
c4.metric("Latency", f"{result['latency_ms'] / 1000:.1f}s")

if report.get("applied_floor"):
    st.warning("The rule layer raised the model's assessment. The model on its own "
               "rated this lower; the rules are never lowered to match it.")

main, side = st.columns([3, 2])
with main:
    no_attack = a["attack_type"].strip().lower() in ("", "none", "n/a", "benign")
    st.subheader("No attack identified" if no_attack else a["attack_type"])
    tid = a["mitre"]["technique_id"]
    if tid:
        st.markdown(f"**MITRE ATT&CK** [{tid} · {a['mitre']['technique_name']}]({client.attack_url(tid)})")
    st.write(a["summary"])
    if a["recommendations"]:
        st.markdown("**Recommended actions**")
        st.markdown("\n".join(f"{i}. {r}" for i, r in enumerate(a["recommendations"], 1)))
    if a["supporting_lines"]:
        st.markdown("**Evidence**")
        st.code("\n".join(a["supporting_lines"]), language="log")
    ind = {k: v for k, v in a["indicators"].items() if v}
    if ind:
        st.markdown("**Indicators**")
        st.table([{"type": k, "values": ", ".join(v)} for k, v in ind.items()])
with side:
    render_rules(report)
    render_label(a["verdict"], a["severity"], tid)

st.caption(f"`{result['model']}` · prompt `{result['prompt_version']}`")
