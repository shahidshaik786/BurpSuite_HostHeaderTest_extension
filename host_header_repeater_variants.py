# -*- coding: utf-8 -*-
# Name: Host Header Repeater Variants
# Purpose: Generate common Host/Forwarded header variants and send them to Repeater.
# Scope: Right-click a request (Proxy/Target/Repeater), choose "Send Host-Header Test Variants to Repeater".

from burp import IBurpExtender, IContextMenuFactory, IExtensionHelpers
from javax.swing import JMenuItem
from java.util import ArrayList

EVIL_HOST = "evil-attacker.example"
LOCAL_IP  = "127.0.0.1"  # also useful for cache-poisoning/by-pass checks
ALT_PORTS = [80, 81, 443, 4443, 8080, 8443]

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Host Header Repeater Variants")
        callbacks.registerContextMenuFactory(self)
        print("[+] Host Header Repeater Variants loaded")

    # ---------- Context Menu ----------
    def createMenuItems(self, invocation):
        self.invocation = invocation
        menu = ArrayList()
        item = JMenuItem("Send Host-Header Test Variants to Repeater", actionPerformed=self.run_variants)
        menu.add(item)
        return menu

    # ---------- Helpers ----------
    def _bytes(self, arr):
        # burp byte[] -> python bytes
        return bytearray(arr)

    def _replace_or_add_header(self, headers, name, value, add_if_missing=True, allow_duplicate=False):
        new = []
        found = False
        lower = name.lower() + ":"
        for h in headers:
            if h.lower().startswith(lower):
                found = True
                if allow_duplicate:
                    new.append(h)  # keep original
                    new.append("%s: %s" % (name, value))
                else:
                    new.append("%s: %s" % (name, value))
            else:
                new.append(h)
        if add_if_missing and not found:
            new.append("%s: %s" % (name, value))
        return new

    def _remove_header(self, headers, name):
        lower = name.lower() + ":"
        return [h for h in headers if not h.lower().startswith(lower)]

    def _get_service_host_port_proto(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        useHttps = (httpService.getProtocol().lower() == "https")
        return host, port, "https" if useHttps else "http"

    def _set_request_line_absolute_url(self, analyzedReq, body_bytes, headers, service):
        # Convert "GET /path HTTP/1.1" to "GET http://host[:port]/path HTTP/1.1"
        host, port, proto = self._get_service_host_port_proto(service)
        req = headers[0]  # request line
        parts = req.split(" ")
        if len(parts) >= 3 and parts[1].startswith("/"):
            default = (443 if proto == "https" else 80)
            hostport = "%s:%d" % (host, port) if port != default else host
            parts[1] = "%s://%s%s" % (proto, hostport, parts[1])
            headers[0] = " ".join(parts)
        return headers

    def _build(self, headers, body):
        return self.helpers.buildHttpMessage(headers, body)

    def _variants(self, messageInfo):
        req = messageInfo.getRequest()
        analyzed = self.helpers.analyzeRequest(req)
        headers = list(analyzed.getHeaders())
        body = self._bytes(req)[analyzed.getBodyOffset():]
        service = messageInfo.getHttpService()
        tgt_host, tgt_port, tgt_proto = self._get_service_host_port_proto(service)

        variants = []

        # 0) Baseline clone
        variants.append(("00_baseline", headers[:], body))

        # 1) Replace Host with EVIL
        h = self._replace_or_add_header(headers[:], "Host", EVIL_HOST, add_if_missing=True, allow_duplicate=False)
        variants.append(("01_host_replaced", h, body))

        # 2) Duplicate Host (keep legit + add evil)
        h = self._replace_or_add_header(headers[:], "Host", EVIL_HOST, add_if_missing=True, allow_duplicate=True)
        variants.append(("02_host_duplicate", h, body))

        # 3) Add X-Forwarded-Host
        h = self._replace_or_add_header(headers[:], "X-Forwarded-Host", EVIL_HOST, add_if_missing=True)
        variants.append(("03_xfh_added", h, body))

        # 4) Add X-Original-Host
        h = self._replace_or_add_header(headers[:], "X-Original-Host", EVIL_HOST, add_if_missing=True)
        variants.append(("04_xoh_added", h, body))

        # 5) Add X-Host
        h = self._replace_or_add_header(headers[:], "X-Host", EVIL_HOST, add_if_missing=True)
        variants.append(("05_xhost_added", h, body))

        # 6) Add X-Forwarded-Server
        h = self._replace_or_add_header(headers[:], "X-Forwarded-Server", EVIL_HOST, add_if_missing=True)
        variants.append(("06_xfs_added", h, body))

        # 7) Add Forwarded header (RFC 7239)
        fwd_val = 'for=%s;host=%s;proto=%s' % (LOCAL_IP, EVIL_HOST, "http")
        h = self._replace_or_add_header(headers[:], "Forwarded", fwd_val, add_if_missing=True)
        variants.append(("07_forwarded_added", h, body))

        # 8) X-Forwarded-For (localhost chain)
        h = self._replace_or_add_header(headers[:], "X-Forwarded-For", "127.0.0.1, 10.0.0.1", add_if_missing=True)
        variants.append(("08_xff_localchain", h, body))

        # 9) X-Forwarded-Proto downgrade
        h = self._replace_or_add_header(headers[:], "X-Forwarded-Proto", "http", add_if_missing=True)
        variants.append(("09_xfp_http", h, body))

        # 10) Absolute URL in request line (mismatch with Host unchanged)
        h = headers[:]
        h = self._set_request_line_absolute_url(analyzed, body, h, service)
        variants.append(("10_absolute_url", h, body))

        # 11) Host with trailing dot
        h = self._replace_or_add_header(headers[:], "Host", tgt_host + ".", add_if_missing=True, allow_duplicate=False)
        variants.append(("11_host_trailing_dot", h, body))

        # 12) Host with alternate/common ports
        for p in ALT_PORTS:
            hp = "%s:%d" % (tgt_host, p)
            h = self._replace_or_add_header(headers[:], "Host", hp, add_if_missing=True, allow_duplicate=False)
            variants.append(("12_host_port_%d" % p, h, body))

        # 13) Remove Host (edge behavior)
        h = self._remove_header(headers[:], "Host")
        variants.append(("13_host_removed", h, body))

        # 14) Conflicting: keep legit Host, add XFH=evil
        h = self._replace_or_add_header(headers[:], "X-Forwarded-Host", EVIL_HOST, add_if_missing=True)
        variants.append(("14_conflict_host_xfh", h, body))

        return variants

    # ---------- Action ----------
    def run_variants(self, event):
        msgs = self.invocation.getSelectedMessages()
        if not msgs:
            print("[-] No messages selected")
            return

        for idx, mi in enumerate(msgs):
            service = mi.getHttpService()
            host = service.getHost()
            port = service.getPort()
            proto = service.getProtocol()
            for name, hdrs, body in self._variants(mi):
                newReq = self._build(hdrs, body)
                self.cb.sendToRepeater(host, port, proto == "https", newReq, "[HH] %s" % name)

        print("[+] Generated Host/Forwarded variants -> Repeater tabs (prefixed with [HH])")
