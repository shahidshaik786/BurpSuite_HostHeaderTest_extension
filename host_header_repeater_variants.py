# -*- coding: utf-8 -*-
# Name: Host Header Repeater Variants (Enhanced)
# Purpose: Generate rich Host/Forwarded header variants and send them to Repeater with smart tab names.
#
# Usage: Right-click any request in Proxy/Target/Repeater -> "Send Host-Header Test Variants to Repeater"
#
# Notes:
# - Ports restricted to 80,443,8080,8443 per requirement.
# - Multiple target hosts supported (edit TARGET_HOSTS below).
# - Repeater tabs named like "Orderdetails_duplicate_host_HH_03".
# - Safe-by-default: does not auto-send; just prepares tabs for you to fire.
#
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
import re

# ======= CONFIG =======
TARGET_HOSTS = [
    "evil-attacker.example",
    "127.0.0.1",
    "google.com"
]
ALT_PORTS = [80, 443, 8080, 8443]
LOCAL_CHAIN = "127.0.0.1, 10.0.0.1"

# ======= EXTENDER =======
class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Host Header Repeater Variants (Enhanced)")
        callbacks.registerContextMenuFactory(self)
        self._counter = 0
        print("[+] Host Header Repeater Variants (Enhanced) loaded")

    # ---------- Context Menu ----------
    def createMenuItems(self, invocation):
        self.invocation = invocation
        menu = ArrayList()
        menu.add(JMenuItem("Send Host-Header Test Variants to Repeater", actionPerformed=self.run_variants))
        return menu

    # ---------- Helpers ----------
    def _b(self, arr):
        return bytearray(arr)

    def _get_service_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        proto = httpService.getProtocol().lower()
        return host, port, proto

    def _req_headers_body(self, messageInfo):
        req = messageInfo.getRequest()
        ar = self.helpers.analyzeRequest(req)
        headers = list(ar.getHeaders())
        body = self._b(req)[ar.getBodyOffset():]
        return headers, body, ar

    def _set_request_line_absolute_url(self, headers, service, use_evil=None):
        host, port, proto = self._get_service_info(service)
        reqline = headers[0]
        parts = reqline.split(" ")
        if len(parts) < 3:
            return headers
        path = parts[1]
        if not path.startswith("/"):
            return headers
        # choose url host
        if use_evil:
            url_host, url_port, url_proto = use_evil
        else:
            url_host, url_port, url_proto = host, port, proto
        default = 443 if url_proto == "https" else 80
        hostport = "%s:%d" % (url_host, url_port) if url_port != default else url_host
        parts[1] = "%s://%s%s" % (url_proto, hostport, path)
        headers[0] = " ".join(parts)
        return headers

    def _replace_or_add(self, headers, name, value, allow_duplicate=False, add_if_missing=True):
        low = name.lower() + ":"
        out = []
        found = False
        for h in headers:
            if h.lower().startswith(low):
                found = True
                if allow_duplicate:
                    out.append(h)  # keep original
                    out.append("%s: %s" % (name, value))
                else:
                    out.append("%s: %s" % (name, value))
            else:
                out.append(h)
        if add_if_missing and not found:
            out.append("%s: %s" % (name, value))
        return out

    def _remove(self, headers, name):
        low = name.lower() + ":"
        return [h for h in headers if not h.lower().startswith(low)]

    def _build(self, headers, body):
        return self.helpers.buildHttpMessage(headers, body)

    def _slug_from_path(self, headers):
        # Derive a pretty base name from request path for tab naming
        try:
            reqline = headers[0]
            path = reqline.split(" ")[1]
        except Exception:
            path = "/"
        # take last non-empty segment
        segs = [s for s in path.split("/") if s]
        base = segs[-1] if segs else "root"
        # remove query & ext
        base = base.split("?")[0]
        base = re.sub(r"\.[a-zA-Z0-9]+$", "", base)  # drop file ext
        # TitleCase
        base = re.sub(r"[^a-zA-Z0-9]+", " ", base).strip().title()
        if not base:
            base = "Root"
        return base

    def _safe_proto(self, service):
        # Burp sendToRepeater needs boolean for TLS
        return service.getProtocol().lower() == "https"

    # ---------- Variant Factory ----------
    def _gen_variants(self, messageInfo):
        headers, body, ar = self._req_headers_body(messageInfo)
        service = messageInfo.getHttpService()
        tgt_host, tgt_port, tgt_proto = self._get_service_info(service)
        base_name = self._slug_from_path(headers)

        variants = []  # list of (tab_name, headers, body)

        # 00 Baseline
        variants.append(("%s_baseline_HH_%02d" % (base_name, self._next_id()), headers[:], body))

        # For each candidate target host (evil/local/google), generate combos
        for payload_host in TARGET_HOSTS:

            # 01 Replace Host
            h = self._replace_or_add(headers[:], "Host", payload_host)
            variants.append(("%s_host_replaced_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 02 Duplicate Host (keep legit + add evil)
            h = self._replace_or_add(headers[:], "Host", payload_host, allow_duplicate=True)
            variants.append(("%s_duplicate_host_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 03 X-Forwarded-Host (single)
            h = self._replace_or_add(headers[:], "X-Forwarded-Host", payload_host)
            variants.append(("%s_xfh_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 04 X-Forwarded-Host chain
            h = self._replace_or_add(headers[:], "X-Forwarded-Host", "%s, %s" % (payload_host, tgt_host))
            variants.append(("%s_xfh_chain_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 05 X-Original-Host
            h = self._replace_or_add(headers[:], "X-Original-Host", payload_host)
            variants.append(("%s_xoh_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 06 X-Host
            h = self._replace_or_add(headers[:], "X-Host", payload_host)
            variants.append(("%s_xhost_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 07 X-Forwarded-Server
            h = self._replace_or_add(headers[:], "X-Forwarded-Server", payload_host)
            variants.append(("%s_xfs_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 08 Forwarded (RFC 7239)
            fwd = 'for=%s;host=%s;proto=http' % (LOCAL_CHAIN.split(",")[0], payload_host)
            h = self._replace_or_add(headers[:], "Forwarded", fwd)
            variants.append(("%s_forwarded_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 09 X-Forwarded-For local chain
            h = self._replace_or_add(headers[:], "X-Forwarded-For", LOCAL_CHAIN)
            variants.append(("%s_xff_chain_HH_%02d" % (base_name, self._next_id()), h, body))

            # 10 X-Forwarded-Proto flip (http)
            h = self._replace_or_add(headers[:], "X-Forwarded-Proto", "http")
            variants.append(("%s_xfp_http_HH_%02d" % (base_name, self._next_id()), h, body))

            # 11 X-Forwarded-Proto flip (https)
            h = self._replace_or_add(headers[:], "X-Forwarded-Proto", "https")
            variants.append(("%s_xfp_https_HH_%02d" % (base_name, self._next_id()), h, body))

            # 12 X-Forwarded-Port (80/443/8080/8443)
            for p in ALT_PORTS:
                h = self._replace_or_add(headers[:], "X-Forwarded-Port", str(p))
                variants.append(("%s_xfpPort_%d_HH_%02d" % (base_name, p, self._next_id()), h, body))

            # 13 Origin spoof
            h = self._replace_or_add(headers[:], "Origin", "http://%s" % payload_host)
            variants.append(("%s_origin_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 14 Referer spoof
            h = self._replace_or_add(headers[:], "Referer", "http://%s/" % payload_host)
            variants.append(("%s_referer_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 15 Absolute-URL request line (to evil) while keeping legit Host
            h = headers[:]
            h = self._set_request_line_absolute_url(h, service, use_evil=(payload_host, 80, "http"))
            variants.append(("%s_absurl_to_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 16 Host trailing dot (target)
            h = self._replace_or_add(headers[:], "Host", tgt_host + ".")
            variants.append(("%s_host_trailing_dot_HH_%02d" % (base_name, self._next_id()), h, body))

            # 17 Host spacing trick "Host : evil"
            h = headers[:]
            # remove any existing Host first
            h = self._remove(h, "Host")
            h.append("Host : %s" % payload_host)  # space before colon
            variants.append(("%s_host_space_colon_%s_HH_%02d" % (base_name, payload_host, self._next_id()), h, body))

            # 18 Cache-poison helpers
            h = self._replace_or_add(headers[:], "X-Original-URL", "/")
            variants.append(("%s_xoriginalurl_root_HH_%02d" % (base_name, self._next_id()), h, body))
            h = self._replace_or_add(headers[:], "X-Rewrite-URL", "/")
            variants.append(("%s_xrewriteurl_root_HH_%02d" % (base_name, self._next_id()), h, body))

            # 19 Host with commonly abused ports
            for p in ALT_PORTS:
                default = (p == 80 and tgt_proto == "http") or (p == 443 and tgt_proto == "https")
                hp = "%s:%d" % (payload_host, p) if not default else payload_host
                h = self._replace_or_add(headers[:], "Host", hp)
                variants.append(("%s_host_%s_port_%d_HH_%02d" % (base_name, payload_host, p, self._next_id()), h, body))

        # 20 Remove Host completely (edge behavior)
        h = self._remove(headers[:], "Host")
        variants.append(("%s_host_removed_HH_%02d" % (base_name, self._next_id()), h, body))

        return variants

    def _next_id(self):
        self._counter += 1
        return self._counter

    # ---------- Action ----------
    def run_variants(self, event):
        msgs = self.invocation.getSelectedMessages()
        if not msgs:
            print("[-] No messages selected")
            return
        for mi in msgs:
            service = mi.getHttpService()
            host, port, proto = self._get_service_info(service)
            use_tls = (proto == "https")
            for tab_name, hdrs, body in self._gen_variants(mi):
                req = self._build(hdrs, body)
                self.cb.sendToRepeater(host, port, use_tls, req, "[HH] %s" % tab_name)
        print("[+] Generated Host/Forwarded variants -> Repeater (prefixed [HH])")
