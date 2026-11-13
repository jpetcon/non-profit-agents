"""Turn completed ADK operations into activity entries, excluding stream fragments."""


class ActivityTracker:
    def __init__(self):
        self.last_author = None
        self.seen = set()
        self.frames = 0

    def events(self, event):
        activity = []
        if event.author and event.author != "user" and event.author != self.last_author:
            self.last_author = event.author
            activity.append({"type": "activity", "label": f"Working with {event.author}", "agent": event.author})
        if event.partial:
            return activity
        self.frames += 1
        frame = event.id or f"frame:{self.frames}"
        for index, part in enumerate((event.content.parts if event.content else []) or []):
            for kind, operation, prefix in [
                ("call", part.function_call, "Using"),
                ("response", part.function_response, "Finished"),
            ]:
                if not operation or not operation.name or getattr(operation, "will_continue", False):
                    continue
                # Event identity preserves real repeated calls, even when an
                # upstream provider reuses a call ID such as "0" on later turns.
                key = (frame, kind, index)
                if key not in self.seen:
                    self.seen.add(key)
                    activity.append({"type": "activity", "label": f"{prefix} {operation.name}", "kind": "tool"})
        return activity
