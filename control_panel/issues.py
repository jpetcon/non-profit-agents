"""Small trusted error vocabulary for Chat; never expose SDK exception text."""
import re
import json

from guardrails.policy import PolicyDenied
from guardrails.authorizer import BUNDLE


class ResponseTruncated(Exception):
    """A model ended its reply at the configured generation limit."""


MESSAGES = {
    'response.truncated': ('This reply reached its length limit', 'Any text received so far has been kept. Ask the agent to continue or request a shorter answer.'),
    "sandbox.setup": ("Set up the local tool sandbox", "Sandboxing is on, but its runtime has not passed local checks. Set up or check it in Guardrails. You can explicitly switch it off to use normal execution."),
    "sandbox.profile": ("Review local sandbox access", "This local connection needs a current sandbox access profile in Guardrails before it can start."),
    "sandbox.cleanup": ("Check sandbox cleanup", "Local sandbox permissions need cleanup. Use Check again in Guardrails before starting another sandboxed operation."),
    "sandbox.platform": ("Sandbox unavailable on this system", "This operating system cannot run the selected sandbox. Review the sandbox choice in Guardrails."),
    "sandbox.busy": ("A local sandbox operation is running", "Wait for the local worker or sandbox setup to finish, then retry your message."),
    "sandbox.environment": ("Review connection environment settings", "A reserved runtime environment mapping prevents sandboxed execution. Review this connection’s advanced settings."),
    "sandbox.command": ("Install the reviewed local command", "The command approved for this connection is not installed. Review its installation and sandbox access."),
    "sandbox.output": ("Local tool output limit reached", "The local worker returned too much output. Narrow the request and try again."),
    "connection.auth_required": ("Sign in to your connection", "An assigned MCP connection needs sign-in or renewed permission. Connect it here, then retry your message in this chat."),
    'inference.history': ('Earlier tool context needs attention', 'Earlier tool calls no longer match the current tool definitions. Continue in this chat without the earlier context; the visible transcript and your draft will be kept.'),
    'inference.tool_history': ('Earlier tool context is incomplete', 'A previous response stopped before its tool context completed. Continue in this chat without the earlier context; review completed actions before requesting more work.'),
    'inference.tool_schema': ('A connected tool needs attention', 'A connected tool has a schema the gateway cannot safely validate. Its definition needs correcting or updating before this team can continue.'),
    'data.payment': ('Remove payment details before sending', 'Payment details were detected and the request was blocked. Remove the card number, expiry and security code. These details cannot be sent to models or tools, including in approved personal-data workflows.'),
    'data.personal': ('Remove personal details before sending', 'Recognisable personal or contact details were found. This content is held locally. Remove them from your draft, or use a separately authorised data workflow. Detection cannot identify every personal detail.'),
    'data.history': ('Earlier context needs attention', 'Earlier messages are restricted by the current policy. You can update an applicable policy or continue in this chat without the earlier context. Your saved messages and draft will remain available.'),
    'data.output': ('A response was held back', 'A response contained restricted information and was withheld. Refine the request or review the applicable policy, then continue in this chat.'),
    "model.unreviewed": ("Review this model", "This configured model needs an access review before the team can use it."),
    "model.secret": ("Add your API key", "One of the team’s connections needs a saved API key."),
    "model.limits": ("Check this model’s reply limit", "The model’s output limit could not be determined. Try again if its catalogue is unavailable, or set its published output limit under Guardrails → Advanced overrides → Technical limits."),
    "provider.credentials": ("Check your API key", "The provider did not accept the saved API key. Replace it below."),
    "provider.rate_limit": ("The provider is busy", "The provider has reached a rate limit. Wait a little before trying again."),
    "provider.failed": ("The model could not respond", "Check the model connection below, then return to Chat when you are ready."),
    "gateway.unverified": ("Connect the gateways", "The team’s gateways need to connect with the saved settings."),
    "gateways.updating": ("Connecting your changes", "Your saved changes are connecting automatically. Your draft is safe."),
    "runtime.stopped": ("Emergency stop is on", "Resume agent work when you are ready. This does not approve any pending action."),
    "tokens.setup": ("Choose a token allowance", "AI responses are switched off. Set a monthly token allowance to enable them."),
    "tokens.run": ("This turn needs more tokens", "The context and model calls exceed the total token budget for this agent turn. You can adjust that budget below or start a shorter conversation."),
    "tokens.day": ("Daily token allowance reached", "The team has used its daily token allowance. Wait until tomorrow or adjust the allowance below."),
    "tokens.month": ("Monthly token allowance reached", "The team has used its monthly token allowance. Adjust it below or wait until the next month."),
    "tool.changed": ("Review this changed capability", "A connected tool’s definition has changed. Refresh the connection and review access before using it."),
    "tool.unreviewed": ("Review tool access", "A selected tool needs an access review before this team can use it."),
    "tools.missing": ("Check the team’s tools", "A selected capability is not available to this agent. Test its connection or review access below."),
    'conversation.outdated': ('This team or agent is no longer available', 'The original agent was removed or moved out of this team. The conversation remains readable. Choose an available team to start more work.'),
    "activity.disabled": ("Choose what the team may do", "The requested activity is switched off. Review your organisation’s choices below."),
    "data.destination": ("Review data handling", "This service has not been approved for this conversation’s data. Review the processing arrangements before continuing."),
    "model.processing_evidence": ("Review data handling", "Personal information needs an approved purpose, provider terms and transfer arrangements."),
    "policy.invalid": ("Your policy needs attention", "The saved guardrail configuration is invalid. Restore or correct it before continuing."),
    "policy.blocked": ("This request is restricted", "An organisation policy blocked this request. Review the permitted workflow or refine your request before continuing."),
    "data.secret": ("Remove a secret from the message", "A saved key or secret was detected. Remove it from the message before sending."),
    "data.credential": ("Remove a credential from the message", "Gateway credentials cannot be included in messages. Remove the credential before sending."),
    "data.field": ("Remove restricted information", "The request includes a restricted data field. Use an approved workflow for that information."),
    'data.pattern': ('Remove restricted information', 'The content matched an organisation data rule and was withheld. Revise the draft before trying again.'),
    'validation.invalid': ('Check the request format', 'The request or response failed gateway validation and was withheld.'),
    "payload.size": ("Shorten this request", "The request exceeds the allowed size. Shorten it or start a new conversation."),
    "resource.calls": ("Response limit reached", "This response reached its call limit. Review what has completed before starting more work."),
    "resource.repeated": ("Repeated calls stopped", "The agent repeated the same operation too often. Refine the request before trying again."),
}
for rule, explanation in json.loads((BUNDLE / 'manifest.json').read_text())['rules'].items():
    MESSAGES.setdefault(rule, ('Your organisation’s policy needs review', explanation))


def issue(code, *, actions=None):
    title, message = MESSAGES.get(code, ("This action needs review", "An organisation policy blocked this action. Review the relevant requirements before continuing."))
    return {"code": code, "title": title, "message": message, "actions": actions or []}


def error_issue(error):
    pending, seen = [error], set()
    while pending and len(seen) < 24:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ResponseTruncated):
            return issue('response.truncated')
        if isinstance(current, PolicyDenied):
            return issue(current.rule if current.rule in MESSAGES else "policy.blocked")
        body = getattr(current, "body", None)
        response = getattr(current, "response", None)
        if response is not None:
            try:
                body = response.json()
            except Exception:
                pass
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            code = body["error"].get("code")
            if code in MESSAGES:
                return issue(code)
            if body['error'].get('type') == 'policy_denied':
                return issue('policy.blocked')
        status = getattr(current, "status_code", None)
        if status == 401:
            return issue("provider.credentials")
        if status == 429:
            return issue("provider.rate_limit")
        # Some SDK fallback wrappers retain only a string. Recognise trusted
        # rule IDs, but never render any part of that exception or traceback.
        text = str(current)[:20000]
        for code in MESSAGES:
            if re.search(r"(?<![a-z_.])" + re.escape(code) + r":", text):
                return issue(code)
        if text.startswith(("Assigned tools are unavailable", "Could not validate assigned tools", "Could not load assigned tools")):
            return issue("tools.missing")
        pending.extend(e for e in [getattr(current, "__cause__", None), getattr(current, "__context__", None), getattr(current, "original_exception", None), *getattr(current, "exceptions", ())] if isinstance(e, BaseException))
    return issue("provider.failed")
