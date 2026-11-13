"""Versioned, executable-code-owned catalogue. Never loaded from a model/server."""
from copy import deepcopy

REVISION = "2026-11-06.1"
CATEGORIES = ["Research", "Analytics & advertising", "Supporters", "Email", "Content & documents", "Social", "Experimentation", "Events"]


def field(key, label, *, required=True, secret=False, hint=""):
    return {"key": key, "label": label, "required": required, "secret": secret, "hint": hint}


def capability(key, label, description, sensitivity="public"):
    return {"id": key, "label": label, "description": description, "data_class": sensitivity}


REPORTS = capability("reports", "Read campaign performance", "Read existing campaigns and aggregate performance. No spending or changes.")
RECORDS = capability("records", "Read selected supporter information", "Read approved supporter fields. Personal-data workflow authorisation is required.", "personal")
CONTENT = capability("content", "Read existing content", "Read existing pages, posts or campaigns; draft new content locally.")
DOCUMENTS = capability("documents", "Search selected documents", "Search and read documents only in the folders or libraries you select.", "personal")
EXPERIMENTS = capability("experiments", "Read experiments and results", "Read existing experiment configuration and results. No launches or changes.")


def native(id, name, category, auth, capabilities, fields=(), *, source, prerequisite="", version="v1"):
    return {"id": id, "name": name, "category": category, "route": "native", "authentication": auth, "capabilities": capabilities, "fields": list(fields), "source": source, "prerequisite": prerequisite, "api_version": version, "revision": REVISION, "description": capabilities[0]["description"], "read_only": True}


def hosted(id, name, category, url, capabilities, *, source, authentication="oauth", fields=(), prerequisite="", read_tools=()):
    return {"id": id, "name": name, "category": category, "route": "hosted", "url": url, "authentication": authentication, "capabilities": capabilities, "fields": list(fields), "source": source, "prerequisite": prerequisite, "read_tools": list(read_tools), "revision": REVISION, "description": capabilities[0]["description"], "read_only": True}


CATALOGUE = [
    {"id": "masterbrand", "name": "Masterbrand", "category": "Research", "route": "installed", "description": "Your organisation’s existing strategy, audience and brand tools.", "capabilities": [capability("brand", "Read Masterbrand", "Use existing strategy and brand tools.")], "revision": REVISION},
    {"id": "google", "name": "Google Analytics", "category": "Analytics & advertising", "route": "local_mcp", "publisher": "Google Analytics", "description": "Read Analytics reports using Google’s official local server.", "command": ["uvx", "--from", "analytics-mcp==1.0.0", "analytics-mcp"], "source": "https://github.com/googleanalytics/google-analytics-mcp", "authentication": "google_adc", "capabilities": [REPORTS], "revision": REVISION},
    {"id": "brave", "name": "Brave Search", "category": "Research", "route": "local_mcp", "publisher": "Brave", "description": "Search public web and news sources using your Brave API key.", "command": ["npx", "-y", "@brave/brave-search-mcp-server@2.1.4", "--transport", "stdio"], "source": "https://github.com/brave/brave-search-mcp-server", "authentication": "key", "capabilities": [capability("search", "Search public sources", "Read public search results.")], "revision": REVISION},
    native("web", "Web page retrieval", "Research", "none", [capability("pages", "Read public web pages", "Retrieve public HTTPS pages with source citations. No sign-in or browser automation.")], source="https://modelcontextprotocol.io/legacy/concepts/tools"),
    native("google_ads", "Google Ads", "Analytics & advertising", "google_api", [REPORTS], source="https://developers.google.com/google-ads/api/docs/start", version="v26", prerequisite="Enable Google Ads API access for your Google Cloud project. The OAuth scope permits broader access; this connector exposes reads only."),
    native("meta_ads", "Meta Ads", "Analytics & advertising", "token", [REPORTS], source="https://developers.facebook.com/docs/marketing-api/insights/", version="v27.0", prerequisite="A Meta app or system-user token with ads_read and access to the selected advertising accounts."),
    native("search_console", "Google Search Console", "Analytics & advertising", "google_api", [capability("search", "Read search performance and indexing", "Read search metrics, sitemap information and URL inspection results.")], source="https://developers.google.com/webmaster-tools/about", version="v3"),
    hosted("salesforce", "Salesforce", "Supporters", "", [RECORDS], source="https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/client-connection-overview.html", fields=[field("server_url", "Salesforce hosted MCP server link")], prerequisite="An administrator must enable a Salesforce hosted data MCP server and register this client. Developer documentation servers do not provide CRM records.", read_tools=["query_records", "get_record", "list_objects", "describe_object"]),
    native("raisers_edge", "Blackbaud — Raiser’s Edge NXT", "Supporters", "blackbaud", [RECORDS, capability("gifts", "Read fundraising information", "Read approved gift information without payments or Gift Aid submissions.", "personal")], [field("subscription_key", "SKY API subscription key", secret=True)], source="https://developer.blackbaud.com/skyapi/products/raisersedge", prerequisite="Create a SKY application and enable it in your Blackbaud environment."),
    native("blackbaud_crm", "Blackbaud CRM", "Supporters", "blackbaud", [RECORDS, capability("gifts", "Read fundraising information", "Read a constituent’s fundraising summary. No revenue changes.", "personal")], [field("subscription_key", "SKY API subscription key", secret=True)], source="https://developer.blackbaud.com/skyapi/products/crm", prerequisite="Enable SKY API for your Blackbaud CRM environment and register a SKY application."),
    native("beacon", "Beacon", "Supporters", "key", [RECORDS], [field("account_id", "Beacon account ID")], source="https://guide.beaconcrm.org/en/articles/5720215-beacon-s-api", prerequisite="API access and an administrator-issued API key are required. Select approved record types after connecting."),
    native("mailchimp", "Mailchimp", "Email", "key", [REPORTS, CONTENT, capability("audiences", "Read approved audience information", "Read audience summaries. Subscriber exports remain excluded.", "personal")], [field("datacenter", "Mailchimp server prefix", hint="For example us21; shown in your Mailchimp API key settings.")], source="https://mailchimp.com/developer/marketing/api-concepts/api-structure", version="3.0"),
    hosted("brevo", "Brevo", "Email", "https://mcp.brevo.com/v1/brevo/mcp", [REPORTS, CONTENT, capability("audiences", "Read approved audience information", "Read selected contact-list information.", "personal")], source="https://developers.brevo.com/docs/mcp-protocol", authentication="key", prerequisite="Generate a Brevo MCP token. Regular SMTP credentials are not MCP tokens.", read_tools=["get_email_campaigns", "get_email_campaign", "get_email_campaign_report", "get_lists", "get_contacts_from_list"]),
    native("engaging_networks", "Engaging Networks", "Email", "session", [RECORDS, CONTENT], [field("region", "Data centre", hint="ca, us or us2")], source="https://knowledge.engagingnetworks.net/datareports/engaging-networks-services-rest-services", version="6.5", prerequisite="An API user with VIEW permissions and your network’s IP allowlisting is required."),
    hosted("wordpress_com", "WordPress.com", "Content & documents", "https://public-api.wordpress.com/wpcom/v2/mcp/v1", [CONTENT], source="https://developer.wordpress.com/docs/mcp/connect-custom-mcp-client/", read_tools=["wpcom-mcp-list-sites", "wpcom-mcp-get-site", "wpcom-mcp-list-posts", "wpcom-mcp-get-post", "wpcom-mcp-list-pages", "wpcom-mcp-get-page"]),
    native("wordpress", "WordPress — self-hosted", "Content & documents", "basic", [CONTENT], [field("site_url", "Website address"), field("username", "WordPress username")], source="https://developer.wordpress.org/rest-api/", version="wp/v2", prerequisite="Use a dedicated WordPress account and application password. Your site must support HTTPS."),
    hosted("contentful", "Contentful", "Content & documents", "https://mcp.contentful.com/mcp", [CONTENT], source="https://www.contentful.com/developers/docs/mcp/model-context-protocol-mcp-server/", fields=[field("region", "Account region", required=False, hint="global or eu")], prerequisite="Install the Contentful MCP app in each authorised space/environment.", read_tools=["get_spaces", "get_environments", "get_entries", "get_entry", "get_content_types", "get_assets", "get_asset"]),
    native("meta_social", "Meta — Facebook & Instagram", "Social", "token", [capability("social", "Read posts and engagement", "Read selected page/Instagram posts and aggregate engagement. No posting or messages.")], source="https://developers.facebook.com/docs/graph-api/", version="v27.0", prerequisite="A provider-issued token with read access to the selected Facebook pages and Instagram professional accounts."),
    native("linkedin", "LinkedIn", "Social", "linkedin", [capability("social", "Read organisation posts and analytics", "Read organisation content and aggregate engagement allowed by your LinkedIn API products.")], source="https://learn.microsoft.com/en-us/linkedin/marketing/", version="202610", prerequisite="An approved LinkedIn application with the relevant Community Management API access is required. Personal-profile scraping is not supported."),
    hosted("buffer", "Buffer", "Social", "https://mcp.buffer.com/mcp", [capability("social", "Read channels, posts and analytics", "Read existing channel content and performance. New posts stay local drafts.")], source="https://developers.buffer.com/guides/integrations/mcp", read_tools=["get_channels", "list_channels", "get_posts", "list_posts", "get_post", "get_post_analytics", "get_channel_analytics"]),
    native("google_drive", "Google Drive", "Content & documents", "google_api", [DOCUMENTS], source="https://developers.google.com/workspace/drive/api/guides/about-sdk", version="v3", prerequisite="Enable the Drive API. Choose the folders this connection may search."),
    native("sharepoint", "SharePoint", "Content & documents", "microsoft", [DOCUMENTS], [field("tenant", "Microsoft tenant ID", hint="Your organisation’s tenant ID or verified tenant domain.")], source="https://learn.microsoft.com/en-us/graph/api/resources/sharepoint", version="v1.0", prerequisite="An Entra administrator must register a public client and approve the required read permissions. Choose specific libraries after connecting."),
    native("vwo", "VWO", "Experimentation", "key", [EXPERIMENTS], [field("account_id", "VWO account ID")], source="https://developers.wingify.com/reference/campaigns", version="v2", prerequisite="API access and an API token for your VWO/Wingify account are required. This preset uses the documented app.wingify.com API."),
    hosted("optimizely", "Optimizely", "Experimentation", "", [EXPERIMENTS], source="https://docs.optimizely.com/experimentation-strategy/docs/optimizely-experimentation-mcp-server-example-prompts", fields=[field("server_url", "Optimizely Experimentation MCP server link", hint="Use the Experimentation endpoint supplied by your account administrator.")], prerequisite="Your Optimizely account must have Experimentation MCP access enabled. Separate AI/Mark operations are not included.", read_tools=["list_projects", "get_project", "list_experiments", "get_experiment", "get_experiment_results", "list_flags", "get_flag"]),
    native("eventbrite", "Eventbrite", "Events", "token", [capability("events", "Read events and aggregate sales", "Read event details and aggregate sales. Attendee-level records are excluded.")], source="https://www.eventbrite.com/platform/api", version="v3"),
    {"id": "remote", "name": "Another MCP server", "category": "Advanced", "route": "custom", "description": "Connect a custom remote MCP server or review local commands.", "authentication": "detect", "capabilities": [], "revision": REVISION},
]


def preset(identifier):
    for value in CATALOGUE:
        if value["id"] == identifier:
            return deepcopy(value)
    raise ValueError("Choose a maintained connector preset or Advanced custom connection.")


def catalogue():
    return deepcopy(CATALOGUE)


def hosted_url(value, url):
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in {None, 443}:
        raise ValueError("Use the provider’s HTTPS MCP endpoint without credentials or query parameters.")
    if value["url"]:
        allowed = [value["url"]]
        if value["id"] == "contentful":
            allowed.append("https://mcp.eu.contentful.com/mcp")
        if url.rstrip("/") not in allowed:
            raise ValueError("Use this preset’s documented provider endpoint.")
    else:
        host = parsed.hostname or ""
        if value["id"] == "salesforce":
            valid = host == "api.salesforce.com" and parsed.path.startswith("/platform/mcp/v1/")
        else:
            valid = (host.endswith(".optimizely.com") or host.endswith(".optimizely.net")) and "mcp" in parsed.path.lower()
        if not valid:
            raise ValueError("Ask your administrator for the vendor-hosted account-access MCP endpoint.")
    return url


def managed_check(spec):
    managed = spec.get("managed")
    if not managed:
        return None
    value = preset(managed["preset"])
    if managed["revision"] != value["revision"]:
        raise ValueError("This connector’s maintained definition changed. Review its information access again.")
    return value


def hosted_read_allowed(spec, tool, arguments=None):
    value = managed_check(spec)
    if not value or value["route"] != "hosted":
        return True
    # Tool annotations, names with a 'read' prefix, and model claims confer no
    # permission. Only these maintained contracts plus exact schema review count.
    if tool not in value["read_tools"]:
        return False
    arguments = arguments or {}
    def safe(value):
        if isinstance(value, dict):
            return all(k.lower() not in {"method", "operation", "action", "mutation", "execute", "code", "script", "url", "endpoint"} and safe(v) for k,v in value.items())
        return not isinstance(value, list) or all(safe(v) for v in value)
    return safe(arguments)


def capability_tools(value, capability):
    if value["id"] == "brevo":
        return {"reports":["get_email_campaign_report"], "content":["get_email_campaigns","get_email_campaign"], "audiences":["get_lists","get_contacts_from_list"]}[capability]
    return value.get("read_tools", [])


def source_class(value, tool):
    levels = ["public", "personal", "sensitive"]
    classes = [c["data_class"] for c in value["capabilities"] if tool in capability_tools(value,c["id"])]
    return max(classes or ["sensitive"], key=levels.index)


HOSTED_BOUNDARIES = {"account_id", "site_id", "space_id", "organization_id", "org_id", "project_id", "list_id", "environment_id", "channel_id"}


def resources_bound(rule):
    fields = set((rule.input_schema or {}).get("properties", {})) & HOSTED_BOUNDARIES
    return not (fields - set(rule.fixed_arguments))
