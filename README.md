# Kindred · Local agent studio for charities

Kindred is a private, single-user workspace for creating and using AI teams in a
charity or nonprofit. It brings agents, organisational guidance, research tools,
connected services, safety controls, usage limits, and conversations into one
browser interface running on your computer. If you are looking for a managed, secure, multi-user service, I would highly recommedn somehting like AWS Bedrock, Google Vertex AI or Azure AI Foundry. 

This README has two parts:

- [Guide for charity and nonprofit teams](#guide-for-charity-and-nonprofit-teams)
  explains the product in plain language and covers everyday use.
- [Engineering guide](#engineering-guide) covers installation, architecture,
  configuration, integrations, security behaviour, and testing.

## Guide for charity and nonprofit teams

### What Kindred helps you do

Kindred lets you organise AI assistants into teams. A team has a coordinator and
can have specialists for work such as supporter research, fundraising strategy,
campaign writing, search, social media, conversion, partnerships, and performance
analysis.

You can use Kindred to:

- research public information and read approved connected sources;
- prepare strategies, campaign plans, briefs, and draft content;
- keep outputs aligned with your organisation's mission, audiences, values, and
  writing style through the **Masterbrand**;
- give different agents access to only the tools they need;
- set token allowances and decide which types of charity work are permitted;
- review sensitive or consequential actions before they happen; and
- keep separate conversation histories for each team and agent.

Kindred supports people making decisions; it does not replace them. Check factual
claims, sources, calculations, tone, permissions, and legal or professional advice
before using an answer. The included guardrails support good working practices but
do not certify legal, regulatory, fundraising, safeguarding, or data-protection
compliance.

### What this version does not do

The maintained connections are deliberately read-only. They can retrieve approved
information, but they do not send supporter communications, publish content, change
CRM records, launch advertising or experiments, make payments, or spend money.
Drafts stay in the conversation for a person to review.

Kindred is also not a shared online service. It is designed for one trusted person
using one computer. It does not include user accounts, organisational login, shared
workspaces, or remote access. Do not expose the app through a public proxy or share
its private browser-pairing link.

### Before you begin

Ask a technical colleague to complete the installation if you are not comfortable
using a terminal. You will need:

- a computer on which you are allowed to install and run local software;
- internet access for the first installation and for any online AI or connected
  services you choose to use;
- an API key for an AI provider (the supplied setup uses OpenRouter); and
- a Brave Search API key if you keep the supplied Brave research tools assigned
  to agents (otherwise remove those tool assignments before chatting).

Provider accounts and external services may charge for use. Kindred's token
allowances limit AI usage by token count; they are not a budget in pounds and do
not include charges from connected services.

### Start Kindred

The one-time technical setup and normal launch both use these commands from the
project folder:

```bash
uv sync
uv run python -m control_panel
```

The first command installs the required software. The second starts Kindred and
normally opens it in your browser. The terminal also prints a private, one-use
pairing link. Do not share that link.

Keep the terminal window open while you use Kindred. Closing the browser does not
stop the app. When you finish, return to the terminal and press **Ctrl+C** to stop
Kindred and the background services it started.

### Complete the first-time setup

Use the left-hand navigation in this order:

1. **Overview** — check the setup checklist and the status of the two gateways.
2. **Secrets** — add `OPENROUTER_API_KEY` for the supplied models or set up another key for a different provider and
   `BRAVE_API_KEY` if the supplied Brave research tools remain assigned. Secret
   values remain hidden after saving.
3. **Masterbrand** — add your organisation's name, mission, values, strategy,
   audiences, and writing guidance. Agents treat this as your organisation's
   declared position, not as independently verified evidence.
4. **Guardrails** — choose the relevant UK jurisdictions, allowed activities,
   working mode, safeguarding contact, and monthly token allowance. Research and
   drafting are included. The initial allowance is 1,000,000 tokens per month,
   with an automatic 200,000-token daily allowance and a 50,000-token limit per
   turn. You can change these values; leaving the monthly allowance blank switches
   AI responses off.
5. **Models** — review which AI models and providers your agents use. The supplied
   models use OpenRouter, but other supported providers or local Ollama models can
   be added.
6. **Tools & Connections** — connect only the services and information sources you
   want Kindred to read. Choose the permitted accounts, folders, properties, or
   libraries, then choose which agents may use them.
7. **Teams** and **Agents** — review the supplied charity team or create teams for
   different purposes. Each team has one coordinator and can have several
   specialists.
8. **Chat** — choose a team or specialist and start a conversation when Overview
   shows both gateways as ready.

Saving most settings reconnects the affected background service automatically.
If Chat is not ready, follow the setup card shown above the message box; Kindred
never resends a failed or held message without you choosing **Send** again.

### Use Kindred day to day

1. Select the relevant team from **Current team**.
2. Open **Chat** and choose the coordinator for a broad task (it will choose what other agents to call) or a specialist for a
   focused task.
3. State the desired outcome, audience, deadline, constraints, and evidence the
   agent may use. Avoid including unnecessary personal information.
4. Review the answer, sources, assumptions, and activity timeline. Treat generated
   text as a draft until a person has checked it.
5. If Kindred asks for approval, inspect the exact action and arguments. Approvals
   are one-use, expire after five minutes, and cannot override a hard safety denial.
6. Save or publish work through your organisation's normal reviewed process; the
   maintained Kindred connections do not do this for you.

You can change agent instructions for the next turn, and saved policy, model, tool,
or connection changes take effect after the gateways reconnect. If a response is
cut short by a length limit, explicitly ask the agent to continue or to give a
shorter answer.

### Understand privacy and data handling

“Local” means the interface, configuration, secrets, and conversation database are
kept on this computer. It does **not** mean every task stays on the computer. When
you use an online model or connection, the necessary prompt, context, or tool data
is sent to that provider under its terms and your organisation's arrangements.
The supplied OpenRouter routing is global for development and processing may occur
outside Europe. A custom endpoint does not by itself prove where processing occurs.

Use the minimum data needed for a task. Do not paste passwords, API keys, payment-card
details, or unnecessary donor, beneficiary, supporter, or staff information into
Chat. Public-data conversations hold many recognisable contact and personal details
before dispatch and can offer **Remove detected details**, but pattern matching
cannot identify every person or sensitive passage. Changing a data label does not
create consent or authorise processing.

Conversations and local operating data are stored in `.local/`; keys are stored in
`.env`. Both paths are ignored by Git, but anyone with access to the computer or an
unprotected backup may still be able to read them. Protect the device, project
folder, and backups according to your organisation's policies.

### Understand the safety controls

- **Cautious** mode allows approved public research and drafting. A consequential
  action requires review of its exact details.
- **Draft-only** mode blocks consequential actions even if someone offers approval.
- **Emergency stop** revokes active runs and cancels in-flight work. It cannot undo
  an action that an external service has already received.
- Tool access, source selection, data classification, and provider sign-in are
  separate controls. Signing into a service does not automatically give every
  agent access to its information.
- Missing consent, processing evidence, financial evidence, safeguarding review,
  or other required facts can block work. The AI cannot invent those facts or
  approve itself.
- Token limits include prompts, replies, retained context, tool context, retries,
  fallbacks, and follow-up model calls. Cancelled or uncertain calls may retain a
  conservative reservation.

### Common problems

| What you see | What to do |
| --- | --- |
| Chat says the team is not ready | Open the setup card in Chat or check both services on **Overview**. |
| A provider key is missing | Add or replace it in **Secrets**, then wait for reconnection. |
| A model is unavailable | Check its provider key and exact model ID in **Models**. |
| A tool is missing | Check its agent assignment in **Agents** and its status in **Tools & Connections**. |
| A connection needs attention | Reconnect it, choose its information sources, and review its capabilities. |
| A message contains detected details | Remove the details locally, review the draft, and explicitly send again. |
| Earlier chat context remains restricted | Choose **Continue without earlier context** to keep the visible transcript while starting fresh internal context. |
| A response is running incorrectly | Stop that response; use **Emergency stop** if all active work must be revoked. |

### Key terms

| Term | Plain-language meaning |
| --- | --- |
| **Agent** | An AI assistant with a particular role, instructions, model, and set of tools. |
| **Team** | A coordinator plus specialist agents that can divide and combine work. |
| **Model/provider** | The AI model that generates an answer and the company or local service that runs it. |
| **Masterbrand** | Your organisation's mission, strategy, audiences, values, and communication guidance. |
| **Tool/connection** | A controlled way for an agent to read public information or an approved external service. |
| **Gateway** | A local checkpoint between agents and AI providers or tools. Both gateways must be ready for Chat. |
| **Token** | A small unit of text used to measure AI input and output; it is not a currency amount. |
| **MCP** | A standard that lets AI applications discover and call tools with defined inputs and outputs. |

## Engineering guide

### Architecture overview

Kindred is a Python 3.11+ application with a locally served plain HTML, CSS, and
JavaScript frontend. There is no frontend build, CDN, hosted policy service, or
required AWS account.

```text
Browser on 127.0.0.1:8080
           │ pairing cookie, CSRF and local API
           ▼
FastAPI control panel ───── YAML/JSON configuration + .env + .local SQLite
           │
           ▼
Google ADK agent runtime
      ┌────┴─────────────────────┐
      ▼                          ▼
guarded inference gateway    guarded tool gateway
LiteLLM · 127.0.0.1:4000     FastMCP · 127.0.0.1:9000
      │                          │
      ▼                          ├── installed Python tools
AI model providers               ├── native read-only adapters / HTTP tools
                                 └── local or remote MCP servers

Both gateway paths apply scoped identity, assignment checks, Cedar policy,
schema validation, limits, secret checks, and buffered response validation.
```

The main subsystems are:

- `control_panel/`: the FastAPI application, local API, service lifecycle, chat
  persistence, browser pairing, and static interface;
- `agents/`: team and agent configuration plus Google ADK construction and runtime;
- `inference/`: LiteLLM model routing behind the guarded inference gateway;
- `tools/` and `connectors/`: the guarded tool gateway, built-in tools, MCP/HTTP
  registration, authentication, and maintained native connectors;
- `guardrails/`: settings compilation, Cedar authorisation, content validation,
  token accounting, approvals, audit metadata, and network boundaries;
- `models/`: the user-facing model registry; and
- `sandboxing/`: optional SRT isolation for local MCP processes and PDF extraction.

For each chat turn, the control panel loads the conversation and current agent
configuration, then starts an ADK run with short-lived scoped gateway credentials.
Model attempts are authorised and reserve tokens before dispatch. Tool calls are
checked again for team/agent assignment, current schemas, selected sources, data
class, arguments, and required approvals. Complete model and tool responses are
buffered and validated before release. Conversation content is persisted locally;
the audit database records policy metadata without raw prompts or results.

### Install and run

Install [uv](https://docs.astral.sh/uv/), then run these commands from the
repository root:

```bash
uv sync
uv run python -m control_panel
```

`uv sync` includes Kindred’s private Node.js runtime, npm and npx. There is no
separate Node installation or version selection, and your existing Node setup
is unchanged. The first sync needs internet access to download dependencies.

Your browser opens at `http://127.0.0.1:8080` with a private, one-use pairing link.
The same link is printed in the terminal. Keep it private. To use another port:

```bash
uv run python -m control_panel --port 8081
```

Use `--no-browser` if you prefer to open the printed link yourself. A paired
browser stays connected for 12 hours or until the app exits. Restart the app to
obtain a fresh pairing link. Sessions and CSRF tokens are held in memory; secret
values are never returned to the browser or written to browser storage.

### First run: technical checklist

1. Open **Secrets** and add `OPENROUTER_API_KEY` or another key for a different provider. Add `BRAVE_API_KEY` when the
   supplied Brave tools remain assigned, or remove those assignments. Gateway
   credentials are issued automatically.
2. Complete **Masterbrand** with your organisation’s mission and writing guidance.
3. Open **Guardrails**. Choose your UK jurisdictions, choose a monthly token allowance
   and select the activities your agents should help with. Research and drafting
   are included. The default is 1,000,000 tokens per month, with a 200,000-token
   daily allowance and 50,000-token budget per turn. No model prices are needed.
4. In **Tools & Connections**, built-in services are ready for configuration.
   Connect the services you use, choose accounts or folders and assign agents.
   Maintained read-only capabilities are selected for new connections; individual
   controls and custom tool reviews are under **Advanced**.
5. Saved changes connect automatically. Once Overview shows both gateways ready,
   start a new conversation.
   Sending messages uses your configured provider and can incur charges.

### Guardrails and authorisation

The dashboard asks for organisation choices. Maintained **Cedar policies** make
local authorisation decisions for both gateways. You do not need to write Cedar,
enter hashes, classify built-in tools, look up token prices or enter an exchange
rate. No hosted policy service or AWS account is required.

The preset UK charity pack covers fundraising eligibility and suppressions,
safeguarding review, campaign references, beneficiary data, restricted funds,
financial evidence and independent authorisation. Select England and Wales,
Scotland and/or Northern Ireland for relevant regulator references. These are
common operational controls with jurisdiction guidance, not a certification of
legal compliance. Core security and safeguarding protections remain active.

**Cautious** mode allows approved public reads and drafts; consequential actions
require review of their exact arguments. **Draft-only** mode blocks consequential
actions even when approval is offered. Selecting an activity does not establish
consent, approve personal-data processing or authorise a payment. Those facts must
come from real records or a trusted integration. Missing evidence blocks execution;
approval cannot override a hard denial. Current built-ins cover public research
and charity context; consent-aware CRM/payment adapters are not included.

Gateway protections enforce schemas, secret checks, response validation, safe
network destinations, limits and transactional token reservations. Complete
responses are checked before streaming output is released. Cedar authorisation
and evaluation errors fail closed. Models cannot provide their own approval or
consent facts. Installed Python tools and local MCP software remain trusted code.

Input and output tokens share the allowance, including follow-up model calls,
tool context and reasoning reported as output usage. Each attempt atomically
reserves a conservative estimate of its UTF-8 context plus the capped output;
reported usage replaces that estimate when available. Cancelled calls and
missing or invalid usage retain their reservation. Limits survive restarts,
include retries and fallbacks, and use Europe/London daily/monthly boundaries.
Daily and per-turn limits can be adjusted under the monthly allowance. A turn
includes its context and all follow-up model calls. Replies use the model’s
supported output limit, bounded by the remaining turn, daily and monthly
budgets; there is no fixed default reply cap. Explicit Advanced output limits
still apply. OpenRouter limits come from its model catalogue; other standard
providers use bundled model metadata. If a model does not publish a known
limit, set its documented limit in Advanced technical limits.
Leaving the monthly field blank switches AI responses off. Token limits apply
to local models too; they are not a pound spending cap. Provider charges still
apply, and external tool charges are not measured by these token limits.

**Emergency stop** revokes active runs and cancels in-flight work. It cannot undo
an action already dispatched. Approval expires after five minutes and is bound to
the exact action, agent, schema and policy revision. Repeated consequential actions
are blocked within a run, including uncertain outcomes. Resume permits new runs.

`guardrails/config.yml` uses version 3 preferences; adapters maintain technical
bindings without price or exchange-rate records. Earlier versions remain readable and migrate on
saving choices, preserving narrower limits and evidence as advanced overrides.
Saves use atomic replacement, backups and revision checks. Saved settings and
connection tests reconnect the affected gateways automatically while chat is idle.
Existing chats continue with the current saved settings after both gateways
report readiness. Changing limits, policy, connections or model settings does
not require a new conversation. Each turn uses fresh scoped credentials and
checks its retained context against the current policy; usage counters remain.
Advanced settings retain the original detailed controls for custom integrations.

`.local/guardrails.sqlite` stores hashed credentials, reservations, approval
metadata, token counters and an audit trail without raw prompts/results. Exact pending arguments
stay in the live gateway process. Audit events expire after 90 days by default;
historical financial records remain independent. Pattern checks supplement source labels;
they cannot identify every sensitive passage or prove factual accuracy.

Public-data mode also holds recognisable contact/personal details before dispatch:
email addresses, UK telephone numbers and postcodes, titled names, numbered street
addresses, dates labelled as dates of birth and National Insurance numbers. Checks
cover the complete model context, tool arguments/results and buffered responses,
including common URL/HTML/Unicode encodings and embedded JSON. Public contact
details can also trigger a hold; patterns cannot establish whose details they are.
Plausible payment-card numbers, configured prohibited fields and recognisable
secrets are blocked independently of the conversation's data label. Card-shaped
numbers with adjacent expiries/security codes, explicitly labelled card numbers
and security codes are held even when the card checksum fails. Local draft
removal removes the detected payment group, including its expiry and security
code. Ordinary standalone dates and short numbers are not treated as cards. JSON
boundaries reject duplicate keys and non-finite numbers; redacted structured
responses must still satisfy their schemas.
Chat offers **Remove detected details** locally, preserves the editable draft and
requires an explicit Send after review. If earlier messages remain restricted,
**Continue without earlier context** keeps the visible transcript and draft in
the same chat, while starting a fresh internal context that excludes those
earlier messages and tool history. It does not resend automatically or approve
an action. Chats whose original agent was removed or moved to another team remain
readable. Model warnings after dispatch
are not a privacy control. Untitled names, indirect identification, arbitrary
encodings and sensitive prose may escape pattern recognition: use minimal data
and reviewed source labels. Personal-data workflows still require activity,
destination and processing-evidence approval; changing a label is insufficient.

Standalone ADK also verifies compatible gateways and uses scoped credentials.
Its credentials last one hour; restart for a fresh run. Developer details are in
[guardrails/README.md](guardrails/README.md).

### Create and use teams

Open **Teams** and choose **New team**. Set its name, purpose, coordinator
instructions, and model. Each team gets its own coordinator. Use **View agents**
to add specialists, assign tools, and choose their supervising agents.

The sidebar’s **Current team** selector switches Overview, Agents, and the team
used for new chats. In **Chat**, start a conversation with a team’s coordinator
or one of its specialists. Saved conversations show their team and agent names.
Each conversation has its own ADK session and history. One response can run at
a time across the workspace.

Use **Edit team** to rename a team, update its purpose, or make it the default
selected on launch. Edit its coordinator in **Agents**. Specialists and their
sub-agents can move between teams by changing their Team and supervising agent;
coordinators remain with their own teams. Review coordinator instructions when
moving specialists if those instructions mention particular agents by name.

Each agent belongs to one team. Validation rejects cycles, duplicate parents,
cross-team references, and agents without a coordinator. Choose **Delete team**
on a team card to remove it and its agents. The confirmation keeps saved
conversations as readable history and leaves shared resources in place. When
deleting the default team, choose its replacement in the confirmation. At least
one team must remain. Model and tool deletion checks consider all teams.

Models, tools, MCP connections, secrets, gateways, and Masterbrand remain shared
workspace resources. Team edits take effect in new conversations; editing an
unrelated team does not invalidate existing chats. Changes to shared models,
tools, or secrets require new chats for all teams. Masterbrand updates remain
available on the next tool call.

Existing single-coordinator configurations are recognized as a **Charity team**.
`agents/config.yml` now supports `teams` and `default_team`; its `root` stays in
sync with the default team for compatibility. The legacy ADK entry point runs
the default team. Set `AGENT_TEAM` to a team identifier to select another team
when using that entry point.

OpenRouter currently uses **global routing for development**. Inference may be
processed outside Europe. The app displays routing for each configured model.

### Choose your models

Open **Models** to add, edit, or remove a model. Give it a readable name, choose
its provider, and enter the exact model ID from that provider. Provider choices
include OpenRouter, OpenAI, Anthropic, Google AI Studio, Mistral AI, Groq,
DeepSeek, Together AI, local Ollama, and other OpenAI-compatible endpoints.
Choose models that support tool calling for your agents.

Select a saved secret for authentication. The editor suggests the provider's
usual secret name, shows whether a value is configured, and lets you add or
replace the key without losing your model draft. Custom secret names work too.
Values stay in `.env`; model configuration stores only `os.environ/NAME`
references. Ollama can run without a provider key.

The affected inference gateway reconnects automatically while chat is idle.
Select your new model in **Agents**, including fallback choices under
advanced settings, then continue your conversation. Changing a provider keeps the
model's internal alias and agent assignments. Existing routing options are
preserved when editing the same provider; switching providers resets those
options. Models used by agents cannot be deleted until reassigned.

Saving a model does not contact its provider, verify tool support, or incur
inference charges. A configured key indicates a stored value, not verified access.
Test explicitly in Chat when ready. Advanced endpoint settings support custom
API bases; endpoints alone do not establish a provider's processing geography.
Shared deployments or providers with advanced authentication remain manageable
in YAML rather than being overwritten by the form. Provider conventions follow
the [LiteLLM provider documentation](https://docs.litellm.ai/docs/providers).

### Connections and MCP authentication

In **Tools & Connections**, every maintained service appears from first launch,
alongside any saved accounts. Unconfigured cards are local catalogue entries:
viewing them creates no connections, grants or downloads. **Add connection**
opens a searchable catalogue with category filters. Maintained connectors use
**Connect → Choose information → Choose agents**. Select account, property,
folder or library names after connecting, approve a capability summary, then
explicitly choose agents. New connections suggest their maintained read-only
capabilities, with individual controls under Advanced. Existing disabled choices
are preserved; newly introduced capabilities and agents are never added to
existing assignments automatically. Hosted definitions that are unknown or
changed still require technical review. Unassigned services do not block Chat
or tool-gateway startup. An incomplete assigned tool blocks its selected team
and offers setup or assignment repair.
Individual tools, custom HTTP tools, commands and registration details are under
**Advanced**. Existing identifiers, assignments and YAML formats remain compatible.

The versioned server-owned registry is in [connectors/registry.py](connectors/registry.py).
It includes these routes:

| Route | Presets |
| --- | --- |
| Existing | Masterbrand, Brave Search, Google Analytics read only |
| Vendor-hosted MCP | Salesforce, Brevo, Contentful, WordPress.com, Buffer, Optimizely Experimentation |
| Local API adapters | Google Ads, Meta Ads, Search Console, Raiser’s Edge NXT, Blackbaud CRM, Beacon, Mailchimp, Engaging Networks, self-hosted WordPress, Facebook/Instagram, LinkedIn, Google Drive, SharePoint, VWO/Wingify, Eventbrite |
| Public research | Bounded HTTPS web-page retrieval, with text extraction and source citations |
| Custom | Remote/local MCP and HTTP tools under Advanced |

New presets expose reads only. Drafts stay in the conversation; no adapter exposes
sending, publishing, advertising spend, payments, mutations or experiment launches.
Native adapters run inside the existing tool gateway, using the same assignments,
scoped credentials, Cedar decisions, validation and audit path. They add no server,
authentication broker, persistent document index or vector database.

Native setup tests read only minimal account/permission metadata and never fetch
supporter records, run performance reports, execute tools or contact models.
Sources are explicitly selected and checked again at execution. Unknown or changed
hosted MCP definitions require administrator review; provider annotations cannot
approve them. Only maintained read-tool contracts can be enabled. Hosted tools
with account/site/space/project/list/channel parameters also need administrator-bound
fixed resource arguments in **Guardrails → Advanced overrides → Advanced tool settings**.
The guided card holds these capabilities until that review is complete. Generic
execution or mutation tools are excluded even when a server exposes them.

Connection, authentication and capability approval remain separate statuses.
**Continue setup** resumes saved connections after a refresh. Reconnect and tool
checks need no Apply changes step. Setup is also available inside Chat, which keeps
the conversation and draft and requires an explicit retry of the message.

#### Provider prerequisites and limits

Google APIs reuse the encrypted Google desktop-client registration; enable the
appropriate Ads, Search Console or Drive APIs in its Cloud project. Analytics ADC
validation remains a separate read-only path. Ads requests only the provider’s
`adwords` scope (there is no read-only variant); fixed read queries enforce the
restriction locally. SharePoint, Blackbaud and LinkedIn offer one-time
**Administrator setup** for application registration and a registered loopback
callback port. Provider consoles, API approval, subscriptions and app registration
remain external administrator tasks. The wizard links to each provider’s instructions.
It never purchases access or claims that AI token limits cap external service charges.

For API-key services, enter the key directly. The app creates a private secret
reference and writes it before publishing its configuration, with revision checks
and rollback. Never enter secret values into YAML. Disconnect invalidates pending
exchanges/refreshes; private native key values are removed without overwriting shared
keys. Reusable application registrations remain encrypted and separate from accounts.
Replacing registration invalidates only accounts using that provider’s registration.

Google Drive searches direct children of selected folders; SharePoint searches
selected document libraries. Retrieval is on demand, with citations and no content
index. Text/HTML/CSV, Google document exports, PDF and DOCX are supported without OCR.
Downloads are limited to 1 MiB; PDF extraction uses a short-lived process with CPU,
decoding and time limits and no service credentials. SharePoint signed downloads must
stay on the selected tenant hostname. Private/reserved addresses, metadata endpoints
and redirects are blocked, including on authentication and download requests.

Queries return bounded first pages (usually 25–50 items), metadata offers at most
50 choices, performance ranges are capped at 90 days and reads have request/deadline
limits. Large collections may require narrower selections or Advanced integration.
Mailchimp exposes audience summaries, not subscriber exports. Blackbaud CRM starts
with constituent and fundraising summaries; Raiser’s Edge also reads gift summaries.
Engaging Networks supporter access is a separate source from selected pages.
Eventbrite never fetches attendee records. LinkedIn requires approved organisation
API access. Salesforce and Optimizely require an administrator-supplied vendor-hosted
account-access endpoint. Documentation-only MCP services are not account connectors.

Drive uses its REST API because its documented MCP needs preview access; SharePoint
uses Microsoft Graph rather than paid Work IQ tooling. Neither route is silently
substituted for an existing custom connection. The catalogue documents its chosen
route and prerequisites. See the official [Drive MCP prerequisites](https://developers.google.com/workspace/drive/api/guides/configure-mcp-server)
and [Work IQ billing information](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/work-iq/).

Source sensitivity has a maintained minimum. Authentication never authorises donor,
beneficiary or document disclosure to an inference provider: the existing approved
purpose, provider terms, transfer arrangements and charity workflows still apply.
Patterns supplement these controls and cannot prove arbitrary prose contains no
personal information.

The regression suite uses fake HTTP/OAuth/MCP services and mocked accounts. Passing
those checks is **not live provider certification**. Validate your organisation’s
API access and enabled capabilities before using real information. No real account
sign-in or paid inference is required by these tests.

Local Google Analytics and Brave presets retain explicit approval of their pinned
package commands. Custom MCP servers retain the individual-tool review flow and
legacy bearer tokens, secret headers and environment settings under Advanced.

For HTTP MCP OAuth, choose **Browser sign-in**, save, and select **Connect**.
Use the address of an actual deployed MCP service. Addresses such as
`https://ga4-mcp.yourdomain.com/mcp` are examples; this app does not host that
remote service for you. The sign-in card offers **Edit connection**, and example
Google Analytics connections can switch to **Set up Google Analytics locally**
without changing their namespace or agent assignments.
Review the sign-in provider and requested permissions, approve the setup, then
open the sign-in link. The local app handles PKCE, the temporary loopback callback,
token refresh and credential persistence. Providers requiring a registered client
can use the advanced client ID, saved client-secret reference, client metadata
document and fixed callback-port settings. Sign-in expires after five minutes.
**Disconnect** clears local credentials immediately and attempts remote revocation
when supported. Gateways never open a sign-in browser themselves.

The **Google Analytics** preset configures the official read-only local
`analytics-mcp==1.0.0` package through `uvx`. One technical administrator completes
**Advanced → Google provider setup** once per installation: choose a Google Cloud
project, enable the Analytics Admin and Analytics Data APIs, configure the OAuth
consent screen, create a Desktop OAuth client and upload its downloaded JSON.
Apps in Google's testing mode need their intended users added as test users.
This Google Cloud setup and the provider's consent page are external; no hosted
authentication broker is used. Everyday users can then sign in and reconnect
from the dashboard without supplying the client file again. New Google
connections use the saved project. Replacing/removing provider setup invalidates
affected sign-ins; disconnecting an account keeps installation setup. Existing
Google user ADC import and per-sign-in desktop-client files remain available
under Advanced choices in the sign-in card. The preset requests Analytics
read-only access and does not enable write tools. Google account permissions
and your app's tool permissions are separate. See the
[official Google setup](https://github.com/googleanalytics/google-analytics-mcp#configure-credentials-).

Authentication credentials are encrypted in `.local/mcp-auth/credentials.sqlite`;
the separate key and database have private file permissions. Neither belongs in
configuration backups or Git. Recently rotated credentials remain available to
redaction checks for 90 days. Local GA4 subprocesses receive a private temporary
credential file that is removed after cleanup or cancellation. With the local
tool sandbox off, trusted local software can access files as your OS user.
Enable the optional sandbox below to restrict local MCP processes and their
credential access.
Google's SDK inside the trusted server handles its own Google API authentication.

Successful sign-in automatically discovers tools without executing them. Review
new capabilities and select their agents in the same setup flow. Refreshing credentials needs no
**Apply changes** step. Chat offers the same sign-in card and keeps the current
conversation and draft; retry explicitly after connecting. Browser authorization
code OAuth and Google user ADC are supported; device-code and enterprise workload
identity flows are not part of this release.

Guided API keys receive unique private references, including explicit mappings
from local server environment names to those references. Shared secrets are not
overwritten. Keys are saved before their referring connection is published, and
failed saves restore previous files. Unfinished or unavailable MCP connections
do not hide other connections' tools. With the local tool sandbox off, custom
local software runs as your OS user; command review alone does not isolate it.

### Optional local tool sandbox

Open **Guardrails → Local tool sandbox** to restrict local MCP connections and
PDF extraction. It is **off by default**, including for existing installations.
Off preserves the normal execution paths and needs no SRT installation. On
requires a working sandbox for discovery, connection tests and execution;
failures block that operation without retrying outside the sandbox.

Choose **Set up sandbox** to install the pinned SRT runtime and maintained Brave
and Analytics packages privately beneath `.local/sandbox/`. Setup needs internet
access; subsequent sandboxed launches use installed entrypoints and do not run
`npx` or `uvx` downloads. Failed setup keeps the previous working installation.
Installation does not enable the switch. You can save On before setup completes,
but covered operations stay blocked until checks pass.

Node.js and npm are included by `uv sync`; sandbox setup uses Kindred’s private
copy automatically. If those bundled files need repair, run the same two start
commands again. macOS also needs ripgrep (`brew install ripgrep`).
Linux needs ripgrep, Bubblewrap and socat (on Debian/Ubuntu,
`sudo apt install ripgrep bubblewrap socat`) and working unprivileged namespaces.
Ask your administrator to resolve a namespace restriction; setup does not change
system security settings.

Windows support is **experimental**, matching
[SRT's Windows alpha status](https://github.com/anthropics/sandbox-runtime/tree/v0.0.81#windows-alpha).
Before setup, Kindred explains the dedicated account and firewall filters and
asks you to confirm. Windows then requests administrator approval. Kindred skips
the full-profile read grant, keeps unrestricted loopback disabled, serializes
its sandbox sessions and requires permission cleanup before another session.
It does not force replacement of another app's SRT installation. Windows has
documented residual permission and network limitations; passing local checks
does not establish the same guarantees on every platform.

The card shows your saved choice separately from **Off**, **Setup needed**,
**Applying**, **Ready** or **Needs attention**. **Check again** runs bounded local
file and network probes with fake data and no provider calls. Finish or stop
active responses, connection tests and workers before changing sandbox settings.
Gateways reconnect automatically; conversations and unsent drafts are retained.
Turning the switch off keeps the installed runtime and restores normal execution
after reconnection.

Brave and Analytics have maintained profiles. Other local MCP commands require
**Advanced → custom connection access** review: grant only existing additional
read paths, write paths and exact public `hostname:port` destinations. Changing a
connection invalidates its review. Private application files, credential stores
and directories containing them cannot be granted. Workers receive private
temporary storage and only their assigned credentials; PDF extraction has no
network or service credentials. Original command approval and tool access
checks still apply.

Coverage is limited to local MCP processes and PDF extraction. ADK, inference
and tool gateways, installed Python handlers and native API adapters retain
their existing execution model. An allowed tool can still use its granted
credentials and services, so retain the existing data and action controls.

### Runtime and everyday operation

- Agent edits apply to the next turn in an existing conversation. Saved settings
  take effect after affected gateways reconnect, with retained context checked
  against the current policy. The original agent must still belong to its team.
- Model, tool, connection, secret and policy saves reconnect affected gateways
  automatically while chat is idle. Testing an unchanged connection does not
  restart gateways. Agent edits need no gateway restart; Masterbrand changes
  apply to the next tool call. Explicitly stopped gateways stay stopped.
- Chat offers setup cards for missing keys, token allowances, tool access and
  connection problems. Fix these in Chat; messages are never resent automatically.
  SDK tracebacks are replaced with safe, actionable explanations.
- When a reply reaches its length limit, Chat keeps the validated text and shows
  a length-limit notice. Ask the agent to continue or request a shorter answer;
  continuation requires an explicit send and uses the existing token allowances.
- Chat checks the selected team’s assigned tools before contacting a model.
  If a capability is missing, check its access in **Guardrails** or test the
  connection in **Tools & Connections**; discovery activates automatically. Availability
  is also checked when an agent loads its tools, so a disconnected provider is
  reported as an error rather than leaving the agent with only handoff tools.
- MCP proxy requests own separate connections and stdio subprocesses. Completing
  or cancelling one request does not disconnect another. The chat activity
  timeline counts completed tool-call events, excluding streaming fragments;
  earlier saved timelines are preserved as recorded.
- Installed Python tools are selectable capabilities. API tools use JSON schemas
  and validated wrappers without generating Python. Path, query, and JSON body
  inputs are supported, with 30-second timeouts and a 1 MB response limit.
- A local MCP executes software on your computer. Only add trusted commands and
  packages. Arguments are passed literally without a shell.
- Closing the browser leaves the app and gateways running. Press **Ctrl+C** in
  the app terminal to exit and stop app-owned gateways and their MCP children.
- Gateways started in another terminal are detected as external. Stop them in
  their original terminals before taking over here. The app never kills by port.
  An older standalone LiteLLM server on port 4000 must be stopped before the
  guarded inference gateway can start. Then choose **Start gateway** on Overview.
- Chat shows gateway startup and connection problems above the message box.
  You can write a draft while the gateways connect; Send becomes available once
  both are ready with the saved settings. Rejected sends keep the draft.

### Configuration, state, and privacy

Existing YAML and JSON files remain authoritative:

| File | Contents |
| --- | --- |
| `agents/config.yml` | Teams, default coordinator, agent hierarchies, instructions, model and tool assignments |
| `tools/config.yml` | Installed tools, `http_tools`, MCP connections |
| `models/model_config.yml` | Friendly model preferences and local inference address |
| `inference/litellm-config.yml` | Reviewed LiteLLM / provider routing |
| `guardrails/config.yml` | Organisation preferences, maintained bindings and optional advanced overrides |
| `tools/custom_tools/lib/strategy.json` | Masterbrand |
| `.env` | Plaintext private keys with owner-only file access where supported |
| `.local/` | SQLite conversations, configuration backups, discovered tools, process identity records, redacted rotating gateway logs |

Keep `.env` and `.local/` private. Both are ignored by Git. Conversations may
contain sensitive material and are stored locally. Configuration saves use atomic
replacement and last-good backups. Concurrent edits are rejected: reload before
saving again. Secret edits preserve unrelated `.env` entries; raw secrets are not
copied into configuration backups. API errors and gateway logs redact configured
secret values.

The server binds only to loopback and uses browser pairing, HttpOnly/SameSite
cookies, origin/host checks, CSRF tokens, a restrictive CSP, and sanitized Markdown.
It is intended for one trusted local user. Do not expose it through a public proxy
or share the pairing link. OAuth, shared accounts, desktop packaging, and OS login
services are outside this version.

### Validation

```bash
uv sync --group dev
LITELLM_LOCAL_MODEL_COST_MAP=True uv run pytest tests --ignore=tests/test_browser.py
uv run python -m playwright install chromium
LITELLM_LOCAL_MODEL_COST_MAP=True uv run pytest tests/test_browser.py
```

Tests use temporary configurations, fake services, fake HTTP/MCP endpoints, and
mocked models. They do not use your `.env` or call paid inference. Browser tests
cover desktop and mobile workflows, keyboard use, and reduced motion. A live
provider check is a separate action: send a chat message when you choose to.
