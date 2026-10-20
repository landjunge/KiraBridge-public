"""Current input widget plus a separately bound Codex turn observation.

Quoted output is not agent activity. Unknown frames/control sequences fail closed.
No input, process operations or identity inference takes place here.
"""

import re


def display_text(text):
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\x1b\[[0-9;:]*m", "", text)
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    unknown = bool(re.search(r"[\x00-\x08\x0b-\x1f\x7f]", text))
    return text, unknown


def input_view(target, text):
    text, unknown = display_text(text)
    if unknown:
        return ""
    if target == "grok" and "╭" in text:
        return text[text.rfind("╭") :]
    if target == "codex":
        prompts = list(re.finditer(r"(?m)^[ \t]*›[^\n]*", text))
        return text[prompts[-1].start() :] if prompts else ""
    return text if target not in {"grok", "codex"} else ""


def assess(target, raw, binding, protocol=None):
    text, controls = display_text(raw)
    view = input_view(target, text)
    base = {
        "target": target,
        "ready": False,
        "state": "unknown",
        "reason": "unknown_input_frame",
        "input_empty": False,
        "protocol_state": protocol.get("state", "unknown") if protocol is not None else "not_bound",
    }

    def result(state, reason):
        return {**base, "state": state, "reason": reason, "ready": state == "ready"}

    if controls or not view:
        return result("unknown", "unsupported_control_sequence" if controls else "prompt_not_found")
    first = view.splitlines()[0].strip()
    if target == "codex":
        # The final input row, not any previous user prompt in visible output.
        empty = bool(re.fullmatch(binding.ready_pattern, first))
        base["input_empty"] = empty
        prelude = text[: text.rfind(view)].rstrip()
        current_block = re.split(r"\n[ \t]*\n", prelude)[-1] if prelude else ""
        current = current_block + "\n" + view
        # Scroll controls belong to the current renderer area, never old quotations.
        if re.search(r"Back to bottom|enter/esc latest", current, re.I):
            return result("scrolled", "current_scroll_controls")
        if not empty:
            return result("input_not_empty", "existing_input_must_not_be_overwritten")
        if protocol and protocol.get("state") == "working":
            return result("working", "bound_codex_turn_active")
        if "tab to queue message" in view:
            return result("working", "current_queue_hint")
        footer = [line.strip() for line in view.splitlines()[1:] if line.strip()]
        known_footer = all(
            re.match(r"^GPT-\S+.*", line) or ("for agents" in line and "? for shortcuts" in line)
            for line in footer
        )
        if not known_footer:
            return result("unknown", "unrecognized_footer_or_dialog")
        # Real progress is above the prompt. An idle protocol observation cannot
        # override a still-rendered current progress row (or vice versa).
        progress = re.search(
            r"(?m)^[ \t]*[•◦]\s+[^\n]*\([^\n]*esc to interrupt[^\n]*",
            current_block,
        )
        if progress:
            return result(
                "unknown" if protocol and protocol.get("state") == "idle" else "working",
                "protocol_display_disagree"
                if protocol and protocol.get("state") == "idle"
                else "current_progress_row",
            )
        if protocol is not None:
            return result(
                "ready" if protocol.get("state") == "idle" else "unknown",
                "bound_codex_turn_idle"
                if protocol.get("state") == "idle"
                else "bound_codex_state_unavailable",
            )
        # Without a bound protocol, ambiguous work words are not an idle proof.
        if binding.busy_pattern and re.search(binding.busy_pattern, text, re.I):
            return result("unknown", "unbound_ambiguous_activity_text")
        return result("ready", "current_empty_widget")

    empty = bool(re.search(binding.ready_pattern, view))
    base["input_empty"] = empty
    if not empty:
        return result("input_not_empty", "existing_input_or_unknown_widget")
    # Grok's existing supported renderer is unchanged in this Codex repair.
    if binding.busy_pattern and re.search(binding.busy_pattern, text, re.I):
        return result("working", "visible_grok_activity")
    if re.search(r"Back to bottom|enter/esc latest", text, re.I):
        return result("scrolled", "current_scroll_controls")
    return result("ready", "current_empty_widget")
