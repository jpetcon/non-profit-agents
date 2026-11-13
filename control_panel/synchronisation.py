"""Coalesce saved changes and reconnect gateways when the app is idle."""
import asyncio


class GatewaySynchronisation:
    def __init__(self, store, services, chat):
        self.store, self.services, self.chat = store, services, chat
        self.requested = asyncio.Event()
        self.state = {"state": "ready", "message": ""}
        self.loop = None

    @property
    def pending(self):
        return self.requested.is_set() or self.state["state"] in {"queued", "updating"}

    def request(self, *paths):
        if paths and all(path in {self.store.agents_path, self.store.brand_path} for path in paths):
            return
        if self.loop:
            try:
                current = asyncio.get_running_loop()
            except RuntimeError:
                current = None
            if current is not self.loop:
                self.loop.call_soon_threadsafe(self.request, *paths)
                return
        self.requested.set()
        self.state = {"state": "queued", "message": "Saved changes will connect automatically when the current response finishes."}

    async def run(self):
        self.loop = asyncio.get_running_loop()
        while True:
            await self.requested.wait()
            # Related saves (including model routing and credentials) form one
            # update. Requests arriving during a restart trigger another pass.
            await asyncio.sleep(.15)
            while (self.chat.active and not self.chat.active.done()) or self.services.lock.locked():
                await asyncio.sleep(.1)
            self.requested.clear()
            self.state = {"state": "updating", "message": "Connecting saved changes…"}
            try:
                statuses = await self.services.apply()
                problems = [s["detail"] for s in statuses if s.get("pending") or s["status"] == "failed"]
                self.state = {"state": "attention" if problems else "ready", "message": self.store.redact(" ".join(problems))}
            except Exception as error:
                self.state = {"state": "attention", "message": self.store.redact(str(error))[:1000]}
            if self.requested.is_set():
                self.state = {"state": "queued", "message": "Connecting the latest saved changes…"}
