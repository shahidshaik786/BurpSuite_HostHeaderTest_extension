# -*- coding: utf-8 -*-
# Name: Host Header Repeater Variants (Compact 30, No Tab Names)
# Purpose: Generate EXACTLY 30 high-signal Host/Proxy header variants and open them in Repeater.
# Usage: Right-click any request (Proxy/Target/Repeater) -> "Send Host-Header Test Variants to Repeater (30)"
#
# Variant set (30 total, including baseline):
#  00 Baseline (1)
#  01-03 Host replaced: evil, 127.0.0.1, google.com (3)
#  04-06 Duplicate Host: evil, 127.0.0.1, google.com (3)
#  07-09 X-Forwarded-Host: evil, 127.0.0.1, google.com (3)
#  10-12 X-Original-Host: evil, 127.0.0.1, google.com (3)
#  13-15 Forwarded: for=127.0.0.1;host=<payload>;proto=http (3)
#  16    X-Forwarded-For: "127.0.0.1, 10.0.0.1" (1)
#  17    X-Forwarded-Proto: http (1)
#  18    X-Forwarded-Proto: https (1)
#  19-22 X-Forwarded-Port: 80, 443, 8080, 8443 (4)
#  23    Absolute-URL request line -> http://evil-attacker.example (1)
#  24    Absolute-URL request line -> http://127.0.0.1 (1)
#  25    Host trailing dot (target.) (1)
#  26    Conflicting headers: keep Host legit + X-Forwarded-Host: evil (1)
#  27    Remove Host header (1)
#  28    Origin: http://evil-attacker.example (1)
#  29    Referer: http://evil-attacker.example/ (1)
#
# Ports restricted to: 80, 443, 8080, 8443
#
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
import re

TARGET_HOSTS = ["evil-attacker.example", "127.0.0.1", "google.com"]
ALT_PORTS = [80, 443, 8080, 8443]
LOCAL_CHAIN = "127.0.0.1, 10.0.0.1"

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Host Header Repeater Variants (Compact 30)")
        callbacks.registerContextMenuFactory(self)
        self._counter = 0
        print("[+] Host Header Repeater Variants (Compact 30) loaded")

    def createMenuItems(self, invocation):
        self.invocation = invocation
        menu = ArrayList()
        menu.add(JMenuItem("Send Host-Header Test Variants to Repeater (30)", actionPerformed=self.run_variants))
        return menu

    # ---------- utilities ----------
    def _b(self, arr): 
        return bytearray(arr)

    def _get_service_info(self, httpService):
        return httpService.getHost(), httpService.getPort(), httpService.getProtocol().lower()

    def _req_headers_body(self, messageInfo):
        req = messageInfo.getRequest()
        ar = self.helpers.analyzeRequest(req)
        headers = list(ar.getHeaders())
        body = self._b(req)[ar.getBodyOffset():]
        return headers, body, ar

    def _replace_or_add(self, headers, name, value, allow_duplicate=False, add_if_missing=True):
        low = name.lower() + ":"
        out, found = [], False
        for h in headers:
            if h.lower().startswith(low):
                found = True
                if allow_duplicate:
                    out.append(h)
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

    def _set_request_line_absolute_url(self, headers, host, port, proto):
        reqline = headers[0]
        parts = reqline.split(" ")
        if len(parts) < 3 or not parts[1].startswith("/"):
            return headers
        default = 443 if proto == "https" else 80
        hostport = "%s:%d" % (host, port) if port != default else host
        parts[1] = "%s://%s%s" % (proto, hostport, parts[1])
        headers[0] = " ".join(parts)
        return headers

    def _next_id(self):
        self._counter += 1
        return self._counter

    # ---------- 30 curated variants ----------
    def _gen_30(self, messageInfo):
        headers, body, ar = self._req_headers_body(messageInfo)
        service = messageInfo.getHttpService()
        tgt_host, tgt_port, tgt_proto = self._get_service_info(service)

        variants = []

        # 00 Baseline
        variants.append((headers[:], body))

        # Host replaced (3)
        for ph in TARGET_HOSTS:
            h = self._replace_or_add(headers[:], "Host", ph)
            variants.append((h, body))

        # Duplicate Host (3)
        for ph in TARGET_HOSTS:
            h = self._replace_or_add(headers[:], "Host", ph, allow_duplicate=True)
            variants.append((h, body))

        # X-Forwarded-Host (3)
        for ph in TARGET_HOSTS:
            h = self._replace_or_add(headers[:], "X-Forwarded-Host", ph)
            variants.append((h, body))

        # X-Original-Host (3)
        for ph in TARGET_HOSTS:
            h = self._replace_or_add(headers[:], "X-Original-Host", ph)
            variants.append((h, body))

        # Forwarded (3)
        for ph in TARGET_HOSTS:
            fwd = "for=127.0.0.1;host=%s;proto=http" % ph
            h = self._replace_or_add(headers[:], "Forwarded", fwd)
            variants.append((h, body))

        # X-Forwarded-For (1)
        h = self._replace_or_add(headers[:], "X-Forwarded-For", LOCAL_CHAIN)
        variants.append((h, body))

        # X-Forwarded-Proto http/https (2)
        h = self._replace_or_add(headers[:], "X-Forwarded-Proto", "http")
        variants.append((h, body))
        h = self._replace_or_add(headers[:], "X-Forwarded-Proto", "https")
        variants.append((h, body))

        # X-Forwarded-Port (4)
        for p in ALT_PORTS:
            h = self._replace_or_add(headers[:], "X-Forwarded-Port", str(p))
            variants.append((h, body))

        # Absolute-URL request line (2)
        h = self._set_request_line_absolute_url(headers[:], "evil-attacker.example", 80, "http")
        variants.append((h, body))
        h = self._set_request_line_absolute_url(headers[:], "127.0.0.1", 80, "http")
        variants.append((h, body))

        # Host trailing dot (1)
        h = self._replace_or_add(headers[:], "Host", tgt_host + ".")
        variants.append((h, body))

        # Conflicting: Host legit + XFH evil (1)
        h = self._replace_or_add(headers[:], "X-Forwarded-Host", "evil-attacker.example")
        variants.append((h, body))

        # Remove Host (1)
        h = self._remove(headers[:], "Host")
        variants.append((h, body))

        # Origin + Referer spoof (2)
        h = self._replace_or_add(headers[:], "Origin", "http://evil-attacker.example")
        variants.append((h, body))
        h = self._replace_or_add(headers[:], "Referer", "http://evil-attacker.example/")
        variants.append((h, body))

        # Safety: ensure exactly 30
        return variants[:30]

    def run_variants(self, event):
        msgs = self.invocation.getSelectedMessages()
        if not msgs:
            print("[-] No messages selected")
            return
        for mi in msgs:
            service = mi.getHttpService()
            host, port, proto = self._get_service_info(service)
            use_tls = (proto == "https")
            for hdrs, body in self._gen_30(mi):
                req = self._build(hdrs, body)
                # No custom tab name -> Burp uses compact "Repeater N"
                self.cb.sendToRepeater(host, port, use_tls, req)
        print("[+] Generated 30 curated Host/Proxy variants -> Repeater (auto-named tabs)")
