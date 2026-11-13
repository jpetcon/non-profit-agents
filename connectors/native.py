"""Bounded read operations; neither URLs, HTTP methods nor code come from models."""
from __future__ import annotations

import asyncio
import base64
from datetime import date, timedelta
from html.parser import HTMLParser
import io
import json
import time
import os
from pathlib import Path
import sys
from urllib.parse import quote, urlsplit
import zipfile
import xml.etree.ElementTree as ET

import httpx
import jsonschema
from fastmcp import FastMCP
from fastmcp.tools import Tool
from fastmcp.tools.base import ToolResult
from pydantic import PrivateAttr

from guardrails.network import transport_for, origin
from guardrails.policy import PolicyDenied, canonical
from guardrails.validation import strict_json
from tools.definitions import MCPSpec
from tools.mcp_auth import CredentialVault, AuthenticationRequired
from .auth import access_token, protect, provider_name
from .registry import preset, managed_check

MAX_BYTES = 1024 * 1024


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []; self.hidden = 0
    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden += 1
        if tag in {"p", "div", "br", "li", "h1", "h2", "h3"}:
            self.parts.append("\n")
    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "template"} and self.hidden:
            self.hidden -= 1
    def handle_data(self, data):
        if not self.hidden:self.parts.append(data)


def text_content(data, content_type):
    mime = content_type.split(";")[0].lower()
    if mime == "application/pdf":
        raise ValueError("PDF extraction requires the bounded document worker.")
    elif mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entry = archive.getinfo("word/document.xml")
            if entry.file_size > MAX_BYTES or entry.compress_size == 0 or entry.file_size / entry.compress_size > 100:
                raise ValueError("The document exceeds the extraction limit.")
            raw = archive.read(entry)
            if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
                raise ValueError("Document entities are unsupported.")
            result = " ".join(ET.fromstring(raw).itertext())
    elif mime in {"text/plain", "text/markdown", "text/csv", "application/json", "text/html"}:
        result = data.decode("utf-8")
        if mime == "text/html":
            parser = PlainText(); parser.feed(result); result = "".join(parser.parts)
    else:
        raise ValueError("This file format is not supported. Use text, PDF or DOCX without OCR.")
    if len(result.encode()) > MAX_BYTES:
        raise ValueError("The extracted document is too large. Narrow the document selection.")
    return result


async def extract(data, content_type, *, root=None, policy=None):
    if content_type.split(';')[0].lower() != 'application/pdf':
        return text_content(data, content_type)
    if root is not None:
        from sandboxing.runtime import SandboxRunner
        worker = Path(__file__).with_name('extract_pdf.py')
        code, output = await SandboxRunner(root).run([sys.executable, '-I', str(worker)], input=data, env={'GCE_METADATA_DISABLED': 'true'}, policy=policy, extra_reads=[worker])
        if code:
            raise ValueError('Could not safely extract this PDF within the document limits. Use a smaller text document.')
        return output.decode('utf-8')
    process=await asyncio.create_subprocess_exec(sys.executable, '-I', str(Path(__file__).with_name('extract_pdf.py')), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env={'PATH':os.defpath,'LANG':'C.UTF-8'})
    try:
        async with asyncio.timeout(7):
            output,_=await process.communicate(data)
        if process.returncode or len(output)>MAX_BYTES:
            raise ValueError('Could not safely extract this PDF within the document limits. Use a smaller text document.')
        return output.decode('utf-8')
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


def operations(spec):
    p = preset(spec["native"]["provider"])
    result = []
    for cap in p["capabilities"]:
        if p["id"] == "web":
            definitions = [("fetch_page", "Read a public HTTPS web page", {"url": {"type": "string", "maxLength": 2048}}, ["url"])]
        elif cap["id"] == "documents":
            definitions = [("search_documents", "Search selected document sources", {"resource": {"type": "string", "maxLength": 512}, "query": {"type": "string", "maxLength": 300}}, ["resource", "query"]), ("read_document", "Read a document in a selected source", {"resource": {"type": "string", "maxLength": 512}, "document_id": {"type": "string", "maxLength": 256}}, ["resource", "document_id"])]
        else:
            properties = {"resource": {"type": "string", "maxLength": 512}}
            required = ["resource"]
            if cap["id"] in {"reports", "search"}:
                properties.update(start_date={"type": "string", "maxLength": 10}, end_date={"type": "string", "maxLength": 10})
            if cap["id"] == "records" or (p["id"] == "blackbaud_crm" and cap["id"] == "gifts"):
                properties["record_id"] = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$", "maxLength": 128}
                required.append("record_id")
            if p["id"] == "mailchimp" and cap["id"] == "content":
                properties["campaign_id"] = {"type":"string", "pattern":"^[A-Za-z0-9_-]{1,128}$"}
            definitions = [("read_"+cap["id"], cap["label"], properties, required)]
            if p["id"] == "search_console":
                definitions += [("inspect_url", "Inspect indexing of a URL in a selected property", {"resource": properties["resource"], "inspection_url": {"type": "string", "maxLength": 2048}}, ["resource", "inspection_url"])]
                definitions += [("list_sitemaps", "Read sitemap indexing information", {"resource": properties["resource"]}, ["resource"])]
        for name, label, properties, required in definitions:
            result.append({"name": name, "label": label, "description": cap["description"], "capability": cap["id"], "data_class": cap["data_class"], "input_schema": {"type": "object", "properties": properties, "required": required, "additionalProperties": False}, "output_schema": {"type": "object", "additionalProperties": True}})
    return result


def values(payload, *keys):
    if isinstance(payload, list):return payload
    if isinstance(payload, dict):
        for key in keys:
            if isinstance(payload.get(key), list):return payload[key]
        for key in ("_data", "data", "results"):
            if isinstance(payload.get(key), dict):
                return values(payload[key], *keys)
    return []


def bounded_page(value):
    """Never release transport pagination URLs (which can contain tokens).

    These tools intentionally expose bounded first pages. Pagination metadata is
    not business data and cannot confer permission to fetch another destination.
    """
    if isinstance(value, list):
        return [bounded_page(v) for v in value]
    if isinstance(value, dict):
        metadata = {"paging", "pagination", "_links", "@odata.nextLink", "nextPageToken"}
        result = {k:bounded_page(v) for k,v in value.items() if k not in metadata}
        if any(value.get(k) for k in metadata):
            result["page_limited"] = True
        return result
    return value


def choice(identifier, label):
    identifier, label = str(identifier), str(label)
    if not identifier or identifier in {"None", ".", ".."} or len(identifier) > 512 or any(ord(c) < 32 for c in identifier):
        raise ValueError("The provider returned an invalid resource identifier.")
    return {"id": identifier, "label": label[:200]}


class NativeClient:
    def __init__(self, name, spec, root, policy, resolve):
        self.name, self.spec, self.root, self.policy, self.resolve = name, spec, root, policy, resolve
        definition = MCPSpec.model_validate(spec)
        self.n = definition.native
        self.p = managed_check(spec)
        self.vault = CredentialVault(root)
        self.handle = self.vault.handle(name, spec, resolve)
        self.requests = 0

    def secret(self, key="api_key"):
        value = self.resolve(self.n.secret_refs.get(key, ""))
        if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise AuthenticationRequired(self.name)
        protect(self.vault, value)
        return value

    async def headers(self):
        if self.handle.generation:
            with self.vault.db() as db:
                if self.handle.row(db)["status"] == "not_connected":
                    raise AuthenticationRequired(self.name)
        provider, kind = self.p["id"], self.p["authentication"]
        if provider_name(self.spec):
            headers = {"Authorization": "Bearer "+await access_token(self.handle, self.policy)}
        elif kind == "none":
            return {}
        elif kind == "basic":
            token = base64.b64encode((self.n.options["username"]+":"+self.secret()).encode()).decode()
            headers = {"Authorization": "Basic "+token}
        elif provider == "mailchimp":
            token = base64.b64encode(("connector:"+self.secret()).encode()).decode()
            headers = {"Authorization": "Basic "+token}
        elif provider == "vwo":
            headers = {"token": self.secret()}
        elif provider == "engaging_networks":
            headers = {"ens-auth-token": await self.session_token()}
        else:
            headers = {"Authorization": "Bearer "+self.secret()}
        if kind == "blackbaud":
            headers["Bb-Api-Subscription-Key"] = self.secret("subscription_key")
        if provider == "linkedin":
            headers.update({"LinkedIn-Version": self.p["api_version"], "X-Restli-Protocol-Version": "2.0.0"})
        for value in headers.values():protect(self.vault, value)
        return headers

    async def session_token(self):
        try:
            data = self.handle.read()
        except AuthenticationRequired:
            self.handle = self.vault.reset(self.name, self.spec, self.resolve)
            data = {}
        if data.get("session", {}).get("expires", 0) > time.time()+60:
            return data["session"]["access_token"]
        async with self.handle.lease():
            data = self.handle.read()
            if data.get("session", {}).get("expires", 0) > time.time()+60:
                return data["session"]["access_token"]
            region = self.n.options["region"]
            result = await self.request("POST", f"https://{region}.engagingnetworks.app/ens/service/authenticate", body=self.secret(), authenticated=False)
            token = result.get("ens-auth-token") or result.get("token")
            if not isinstance(token, str) or not token or any(ord(c) < 33 for c in token):
                raise AuthenticationRequired(self.name)
            protect(self.vault, token)
            expires = result.get("expires", 3600000)
            if not isinstance(expires, (int,float)) or not 60000 <= expires <= 86400000:
                raise AuthenticationRequired(self.name)
            self.handle.change(lambda data: data.update(session={"access_token": token, "expires": time.time()+expires/1000}, connected=True), status="connected")
            return token

    def base(self):
        p = self.p["id"]
        if p == "mailchimp":return f"https://{self.n.options['datacenter']}.api.mailchimp.com/3.0"
        if p == "wordpress":return self.n.options["site_url"].rstrip("/")+"/wp-json/wp/v2"
        if p == "engaging_networks":return f"https://{self.n.options['region']}.engagingnetworks.app/ens/service"
        return {"google_ads": "https://googleads.googleapis.com/v26", "search_console": "https://www.googleapis.com/webmasters/v3", "meta_ads": "https://graph.facebook.com/v27.0", "meta_social": "https://graph.facebook.com/v27.0", "raisers_edge": "https://api.sky.blackbaud.com", "blackbaud_crm": "https://api.sky.blackbaud.com", "beacon": "https://api.beaconcrm.org/v1/account/"+self.n.options.get("account_id", ""), "linkedin": "https://api.linkedin.com/rest", "google_drive": "https://www.googleapis.com/drive/v3", "sharepoint": "https://graph.microsoft.com/v1.0", "vwo": "https://app.wingify.com/api/v2/accounts/"+self.n.options.get("account_id", ""), "eventbrite": "https://www.eventbriteapi.com/v3"}.get(p, "")

    async def request(self, method, url, *, params=None, body=None, authenticated=True, binary=False, public=False):
        self.requests += 1
        if self.requests > 12:
            raise PolicyDenied("resource.calls", "Narrow this request to fewer resources.")
        if method not in {"GET", "POST"}:
            raise PolicyDenied("connector.read_only", "This connector exposes reading only.")
        if not public:
            targets = [self.base()]
            if self.p["id"] == "search_console":targets.append("https://searchconsole.googleapis.com/v1/urlInspection/index:inspect")
            if not any(origin(url) == origin(t) and urlsplit(url).path.startswith(urlsplit(t).path) for t in targets):
                raise PolicyDenied("network.target", "The request left its provider API.")
        if method == "POST" and not ((self.p["id"] == "google_ads" and urlsplit(url).path.endswith("/googleAds:search")) or (self.p["id"] == "search_console" and (urlsplit(url).path.endswith("/searchAnalytics/query") or urlsplit(url).path == "/v1/urlInspection/index:inspect")) or (self.p["id"] == "engaging_networks" and urlsplit(url).path.endswith("/authenticate") and not authenticated)):
            raise PolicyDenied("connector.read_only", "This operation is not an approved read query.")
        headers = await self.headers() if authenticated and not public else {}
        headers["Accept-Encoding"] = "identity"
        headers["Accept"] = "application/json" if not binary else "text/plain, text/html, text/csv, text/markdown, application/json, application/pdf, application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        endpoint = str(httpx.URL(url).copy_merge_params(params or {}))
        if authenticated and not public and self.handle.generation:
            self.handle.read()  # Catch disconnect/configuration races before dispatch.
        try:
            async with asyncio.timeout(25):
                async with httpx.AsyncClient(transport=transport_for(endpoint, [url], (), max_bytes=MAX_BYTES, max_requests=1), timeout=20, trust_env=False, follow_redirects=False) as client:
                    async with client.stream(method, endpoint, json=body, headers=headers) as response:
                        if response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise ValueError("Compressed transfer responses are unsupported for bounded connector reads.")
                        if response.status_code in {401, 403}:
                            if provider_name(self.spec):
                                self.handle.change(lambda data: data.update(connected=False), status="reconnect_required")
                            raise AuthenticationRequired(self.name)
                        if response.status_code == 429:
                            raise ValueError("The service’s request limit was reached. Wait before retrying.")
                        if response.status_code != 200:
                            raise ValueError("The provider could not complete this read. Check API access, selected resources and administrator setup.")
                        data = bytearray()
                        async for chunk in response.aiter_bytes(65536):
                            data.extend(chunk)
                            if len(data) > MAX_BYTES:
                                raise ValueError("The service returned too much information. Narrow the request.")
                        if authenticated and not public and self.handle.generation:
                            self.handle.read()
                        if binary:return await extract(bytes(data), response.headers.get("content-type", ""), root=self.vault.root, policy=self.policy)
                        return bounded_page(strict_json(bytes(data)))
        except httpx.RequestError:
            raise ValueError("The service could not be reached. Check the connection and retry.") from None

    async def resources(self):
        """Only account/schema/folder metadata, never reports or supporter reads."""
        p, b = self.p["id"], self.base()
        if p == "web":return [choice("public_https", "Public HTTPS websites")]
        if p == "google_ads":
            result = await self.request("GET", b+"/customers:listAccessibleCustomers")
            choices = []
            for resource in result.get("resourceNames", [])[:10]:
                identifier = resource.split("/")[-1]
                if not identifier.isascii() or not identifier.isdigit():continue
                metadata = await self.request("POST", b+"/customers/"+identifier+"/googleAds:search", body={"query":"SELECT customer.id, customer.descriptive_name FROM customer LIMIT 1"})
                customer = next(iter(metadata.get("results", [])), {}).get("customer", {})
                choices.append(choice(identifier, customer.get("descriptiveName") or "Google Ads account "+identifier))
            return choices
        if p in {"meta_ads", "meta_social"}:
            result = await self.request("GET", b+("/me/adaccounts" if p == "meta_ads" else "/me/accounts"), params={"fields": "id,name" if p == "meta_ads" else "id,name,instagram_business_account", "limit": 50})
            choices = [choice(("page:" if p == "meta_social" else "")+r["id"], r.get("name", r["id"])) for r in values(result, "data")[:50]]
            if p == "meta_social":
                choices += [choice("instagram:"+r["instagram_business_account"]["id"], r.get("name", "Instagram")+" — Instagram") for r in values(result,"data") if r.get("instagram_business_account",{}).get("id")]
            return choices[:50]
        if p == "search_console":
            result = await self.request("GET", b+"/sites")
            return [choice(r["siteUrl"], r["siteUrl"]) for r in result.get("siteEntry", [])[:50]]
        if p in {"raisers_edge", "blackbaud_crm"}:
            token = self.handle.read().get("api_tokens", {})
            if not token.get("environment_id"):
                raise ValueError("Blackbaud did not identify the authorised environment. Ask your administrator to enable environment access.")
            return [choice(token["environment_id"], token.get("environment_name", "Blackbaud environment"))]
        if p == "beacon":
            result = await self.request("GET", b+"/entity_types")
            return [choice(r.get("name") or r.get("id"), r.get("display_name") or r.get("name") or r.get("id")) for r in values(result, "entity_types", "results", "data")[:50]]
        if p == "mailchimp":
            result = await self.request("GET", b+"/", params={"fields": "account_id,account_name"})
            return [choice(result["account_id"], result.get("account_name", "Mailchimp account"))]
        if p == "engaging_networks":
            await self.request("GET", b+"/supporter/fields")
            result = await self.request("GET", b+"/page", params={"type":"nd"})
            return [choice("supporters", "Supporter records accessible to this API user")] + [choice("page:"+str(r["id"]), r.get("name") or r.get("title") or "Engaging Networks page") for r in values(result, "pages", "data")[:49]]
        if p == "wordpress":
            await self.request("GET", b+"/types")
            return [choice(self.n.options["site_url"], urlsplit(self.n.options["site_url"]).hostname)]
        if p == "linkedin":
            result = await self.request("GET", b+"/organizationAcls", params={"q": "roleAssignee", "role": "ADMINISTRATOR", "state": "APPROVED"})
            choices = []
            for item in values(result, "elements")[:10]:
                identifier = item["organization"].removeprefix("urn:li:organization:")
                if not identifier.isascii() or not identifier.isdigit():continue
                metadata = await self.request("GET", b+"/organizations/"+identifier, params={"projection":"(id,localizedName)"})
                choices.append(choice(item["organization"], metadata.get("localizedName") or item.get("organizationName") or item["organization"]))
            return choices
        if p == "google_drive":
            result = await self.request("GET", b+"/files", params={"q": "mimeType = 'application/vnd.google-apps.folder' and trashed = false", "fields": "files(id,name)", "pageSize": 50, "supportsAllDrives": "true", "includeItemsFromAllDrives": "true"})
            return [choice(r["id"], r.get("name", r["id"])) for r in result.get("files", [])[:50]]
        if p == "sharepoint":
            result = await self.request("GET", b+"/sites", params={"search": "*", "$select": "id,displayName,webUrl", "$top": 5})
            choices = []
            for site in values(result, "value")[:5]:
                drives = await self.request("GET", b+"/sites/"+quote(site["id"], safe="")+"/drives", params={"$select": "id,name,webUrl"})
                for drive in values(drives,"value")[:10]:
                    host = urlsplit(site.get("webUrl", "")).hostname or ""
                    if not host.endswith(".sharepoint.com"):continue
                    choices.append(choice(site["id"]+"|"+drive["id"]+"|"+host, site.get("displayName", "SharePoint")+" / "+drive.get("name", "Documents")))
            return choices[:50]
        if p == "vwo":
            result = await self.request("GET", b+"/campaigns", params={"limit": 50,"showDetailedInfo":"false"})
            return [choice(r.get("id"), r.get("name", str(r.get("id")))) for r in values(result, "campaigns", "items", "data")[:50]]
        if p == "eventbrite":
            result = await self.request("GET", b+"/users/me/organizations/")
            return [choice(r["id"], r.get("name", r["id"])) for r in values(result, "organizations")[:50]]
        raise ValueError("This provider has no maintained metadata operation.")

    async def execute(self, operation, arguments):
        op = next((o for o in operations(self.spec) if o["name"] == operation), None)
        if not op or op["capability"] not in self.n.capabilities:
            raise PolicyDenied("connector.read_only", "This information has not been enabled for the connector.")
        jsonschema.validate(arguments, op["input_schema"])
        resource = arguments.get("resource", "public_https")
        if resource not in self.n.resources:
            raise PolicyDenied("connector.resource", "Choose an account or document source enabled for this connection.")
        p, b, r = self.p["id"], self.base(), quote(resource, safe="")
        end = date.fromisoformat(arguments.get("end_date") or date.today().isoformat())
        start = date.fromisoformat(arguments.get("start_date") or (end-timedelta(days=7)).isoformat())
        if start > end or (end-start).days > 90:
            raise ValueError("Choose a date range of at most 90 days.")
        if p == "web":
            url = arguments["url"]
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in {None,443}:
                raise PolicyDenied("network.url", "Use a public HTTPS page without credentials or a custom port.")
            if any(v in url for v in self.vault.secret_values()):
                raise PolicyDenied("data.secret", "Credentials cannot be included in a page address.")
            text = await self.request("GET", url, authenticated=False, public=True, binary=True)
            return {"source": url, "text": text}
        if p == "google_ads":
            if not resource.isdigit():raise ValueError("Choose a valid advertising account.")
            query = f"SELECT campaign.id, campaign.name, campaign.status, metrics.impressions, metrics.clicks, metrics.cost_micros, metrics.conversions FROM campaign WHERE segments.date BETWEEN '{start}' AND '{end}' LIMIT 50"
            return {"data": await self.request("POST", b+f"/customers/{r}/googleAds:search", body={"query": query})}
        if p == "meta_ads":
            return {"data": await self.request("GET", b+f"/{r}/insights", params={"fields": "campaign_id,campaign_name,impressions,clicks,spend,actions", "level": "campaign", "limit": 50, "time_range": json.dumps({"since": str(start), "until": str(end)})})}
        if p == "search_console":
            if operation == "list_sitemaps":
                return {"data": await self.request("GET", b+f"/sites/{r}/sitemaps")}
            if operation == "inspect_url":
                url = arguments["inspection_url"]
                parsed = urlsplit(url)
                expected = resource.removeprefix("sc-domain:") if resource.startswith("sc-domain:") else urlsplit(resource).hostname
                host = parsed.hostname or ""
                if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or not (host == expected or resource.startswith("sc-domain:") and host.endswith("."+expected)) or not resource.startswith("sc-domain:") and not url.startswith(resource):
                    raise PolicyDenied("connector.resource", "The inspected URL must belong to the selected Search Console property.")
                return {"data": await self.request("POST", "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect", body={"inspectionUrl": url, "siteUrl": resource})}
            return {"data": await self.request("POST", b+f"/sites/{r}/searchAnalytics/query", body={"startDate": str(start), "endDate": str(end), "dimensions": ["date"], "rowLimit": 50})}
        if p in {"raisers_edge", "blackbaud_crm"}:
            token = self.handle.read().get("api_tokens", {})
            if resource != token.get("environment_id"):
                raise PolicyDenied("connector.resource", "The environment differs from the authorised Blackbaud account.")
            if op["capability"] == "records":
                path = "/constituent/v1/constituents/"+quote(arguments["record_id"],safe="") if p == "raisers_edge" else "/crm-conmg/constituents/"+quote(arguments["record_id"],safe="")+"/view"
                result = await self.request("GET", b+path)
                return {"data": approved_record(result)}
            if p == "blackbaud_crm":
                result = await self.request("GET", b+"/crm-conmg/constituents/"+quote(arguments["record_id"],safe="")+"/view")
                return {"fundraising": {k:v for k,v in result.items() if k in {"name","last_revenue_date","planned_giver_stage","donor_state","recognition_constituency_text"} and isinstance(v,(str,int,float,bool,type(None)))}}
            route = "/gift/v1/gifts"
            result = await self.request("GET", b+route, params={"limit": 25})
            return {"gifts": [approved_record(v) for v in values(result,"value","gifts","results")[:25]]}
        if p == "beacon":
            result = await self.request("GET", b+f"/entity/{r}/"+quote(arguments["record_id"],safe=""), params={"populate": "false"})
            return {"data": approved_record(result.get("entity", result))}
        if p == "mailchimp":
            # The account returned by metadata is checked again at dispatch.
            account = await self.request("GET", b+"/", params={"fields": "account_id"})
            if str(account.get("account_id")) != resource:raise PolicyDenied("connector.resource", "The Mailchimp account changed; reconnect.")
            if op["capability"] == "content" and arguments.get("campaign_id"):
                return {"data": await self.request("GET", b+"/campaigns/"+quote(arguments["campaign_id"],safe="")+"/content", params={"fields":"plain_text,html,archive_html"})}
            path, fields = {"reports": ("reports", "reports(id,campaign_title,emails_sent,opens,clicks,bounces),total_items"), "content": ("campaigns", "campaigns(id,settings,title,type,status),total_items"), "audiences": ("lists", "lists(id,name,stats),total_items")}[op["capability"]]
            return {"data": await self.request("GET", b+"/"+path, params={"count":25,"fields":fields})}
        if p == "engaging_networks":
            if op["capability"] == "records":
                if resource != "supporters":raise PolicyDenied("connector.resource", "Enable supporter information separately from page access.")
                result = await self.request("GET", b+"/supporter/"+quote(arguments["record_id"],safe=""), params={"includeQuestions":"false","includeMemberships":"false"})
                return {"data": approved_record(result)}
            if not resource.startswith("page:"):raise PolicyDenied("connector.resource", "Choose a selected page.")
            return {"data": await self.request("GET", b+"/page/"+quote(resource[5:],safe=""))}
        if p == "wordpress":
            return {"data": await self.request("GET", b+"/posts", params={"per_page":25,"status":"publish","_fields":"id,title,content,link,date"})}
        if p == "meta_social":
            kind, identifier = resource.split(":",1)
            if kind not in {"page","instagram"} or not identifier.isdigit():raise PolicyDenied("connector.resource", "Choose a verified social account.")
            r = quote(identifier,safe="")
            edge = "/media" if kind == "instagram" else "/posts"
            fields = "id,caption,permalink,timestamp,like_count,comments_count" if edge == "/media" else "id,message,permalink_url,created_time,shares"
            return {"data": await self.request("GET", b+"/"+r+edge, params={"fields":fields,"limit":25})}
        if p == "linkedin":
            return {"posts": await self.request("GET", b+"/posts", params={"q":"author","author":resource,"count":25}), "engagement": await self.request("GET", b+"/organizationalEntityShareStatistics", params={"q":"organizationalEntity","organizationalEntity":resource})}
        if p == "vwo":
            result = await self.request("GET", b+"/campaigns/"+r)
            result = result.get("_data", result)
            data = result.get("campaign", result.get("campaigns", result))
            if isinstance(data,list):data=data[0] if data else {}
            return {"experiment": {k:v for k,v in data.items() if k in {"id","name","type","status","createdOn","percentTraffic","primaryUrl","goals","variations","stats","variationGoalData","dataIntervalRange"}}}
        if p == "eventbrite":
            result = await self.request("GET", b+"/organizations/"+r+"/events/", params={"page_size":25, "expand":"ticket_classes"})
            return {"events": [{k:e[k] for k in ("id","name","url","start","end","status","capacity","ticket_classes") if k in e} for e in result.get("events",[])[:25]]}
        if p in {"google_drive", "sharepoint"}:
            return await self.documents(operation, resource, arguments)
        raise PolicyDenied("connector.operation", "This operation is not available.")

    async def documents(self, operation, resource, arguments):
        b = self.base()
        if self.p["id"] == "google_drive":
            import re
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", resource):raise ValueError("Choose a valid folder.")
            if operation == "search_documents":
                query = arguments["query"].replace("\\", "\\\\").replace("'", "\\'")
                result = await self.request("GET", b+"/files", params={"q": f"'{resource}' in parents and trashed = false and fullText contains '{query}'", "pageSize":25,"fields":"files(id,name,mimeType,webViewLink)","supportsAllDrives":"true","includeItemsFromAllDrives":"true"})
                return {"documents":result.get("files",[])[:25],"scope":"Direct children of the selected folder"}
            identifier = arguments["document_id"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", identifier):raise ValueError("Choose a valid document.")
            path = b+"/files/"+quote(identifier,safe="")
            info = await self.request("GET", path, params={"fields":"id,name,parents,mimeType,webViewLink","supportsAllDrives":"true"})
            if resource not in info.get("parents",[]):raise PolicyDenied("connector.resource", "The document is outside the selected folder.")
            if info.get("mimeType", "").startswith("application/vnd.google-apps."):
                formats = {"application/vnd.google-apps.document":"text/plain", "application/vnd.google-apps.presentation":"text/plain", "application/vnd.google-apps.spreadsheet":"text/csv"}
                if info["mimeType"] not in formats:
                    raise ValueError("This Google document type does not support bounded text export.")
                text = await self.request("GET", path+"/export", params={"mimeType":formats[info["mimeType"]]}, binary=True)
            else:
                text = await self.request("GET", path, params={"alt":"media","supportsAllDrives":"true"}, binary=True)
            return {"title":info.get("name"),"source":info.get("webViewLink") or "https://drive.google.com/file/d/"+identifier+"/view","text":text}
        site, drive, host = resource.split("|")
        if not host.endswith(".sharepoint.com"):raise PolicyDenied("connector.resource", "Choose a verified SharePoint library.")
        base = b+"/drives/"+quote(drive,safe="")
        if operation == "search_documents":
            # Quote literals for Graph's search function and percent-encode the path.
            query = quote(arguments["query"].replace("'", "''"),safe="")
            result = await self.request("GET", base+"/root/search(q='"+query+"')", params={"$top":25,"$select":"id,name,webUrl,parentReference,file"})
            return {"documents":[{k:d[k] for k in ("id","name","webUrl") if k in d} for d in values(result,"value") if d.get("parentReference",{}).get("driveId")==drive][:25]}
        identifier = quote(arguments["document_id"],safe="")
        info = await self.request("GET", base+"/items/"+identifier)
        if info.get("parentReference",{}).get("driveId") != drive:
            raise PolicyDenied("connector.resource", "The document is outside the selected library.")
        download = info.get("@microsoft.graph.downloadUrl", "")
        if urlsplit(download).scheme != "https" or urlsplit(download).hostname != host or urlsplit(download).username or urlsplit(download).password:
            raise PolicyDenied("network.target", "This download requires a separately reviewed destination.")
        protect(self.vault, download)
        text = await self.request("GET", download, authenticated=False, public=True, binary=True)
        return {"title":info.get("name"),"source":info.get("webUrl"),"text":text}


def approved_record(value):
    # Notes, bank details, case records and account-specific unknown fields never
    # enter model context merely because the upstream API returned them.
    allowed = {"id","name","first_name","last_name","email","email_address","type","amount","date","status","c_first_name","c_last_name","c_email","supporterId","suppressed","First Name","Last Name","Email Address","do_not_email","do_not_phone","do_not_mail"}
    return {k:v for k,v in value.items() if k in allowed and isinstance(v,(str,int,float,bool,type(None)))} if isinstance(value,dict) else {}


class NativeTool(Tool):
    _client_factory: object = PrivateAttr()
    _operation: str = PrivateAttr()
    def __init__(self, operation, factory):
        super().__init__(name=operation["name"],description=operation["description"],parameters=operation["input_schema"],output_schema=operation["output_schema"],timeout=40)
        self._client_factory, self._operation = factory, operation["name"]
    async def run(self, arguments):
        async with asyncio.timeout(35):
            result = await self._client_factory().execute(self._operation, arguments)
            return self.convert_result(result)


def server(name, spec, root, policy, resolve):
    mcp = FastMCP("Read-only "+preset(spec["native"]["provider"])["name"])
    for operation in operations(spec):
        mcp.add_tool(NativeTool(operation, lambda: NativeClient(name,spec,root,policy,resolve)))
    return mcp
