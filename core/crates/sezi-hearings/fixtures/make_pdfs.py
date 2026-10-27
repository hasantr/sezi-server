#!/usr/bin/env python3
"""Regenerate the PDF fixtures of sezi-hearings from the text fixtures beside this file.

Every record here is FAKE: hand-written in UYAP's layout with invented names and numbers. No
real minutes may ever be added (docs/HEARINGS_BOT_PLAN.md §9).

Needs LibreOffice (`soffice`) and Ghostscript (`gs`). Run from anywhere:

    python3 core/crates/sezi-hearings/fixtures/make_pdfs.py

What it writes:
  <record>.pdf          each <record>.txt through LibreOffice (embedded subset font + ToUnicode,
                        like a UYAP export)
  long_5p.txt/.pdf,     a criminal record padded with invented witness statements to 5 and 20
  long_20p.txt/.pdf     pages, for the timing test
  scan.pdf              civil_asliye_hukuk rasterised, image only (refused: no-text-layer)
  no_tounicode.pdf      a text layer in a Type0/Identity-H font with no ToUnicode — what a scan
                        "with text" looks like to an extractor (refused: no-text-layer)
  encrypted_user.pdf    needs a password (refused: pdf-encrypted)
  encrypted_owner.pdf   owner password only, opens without one (read)
  bomb.pdf              a 20 KiB file whose page content inflates to 32 MiB (refused:
                        pdf-content-limit)

PDF bytes differ run to run (creation dates, ids); their text does not.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile
import zlib

HERE = pathlib.Path(__file__).resolve().parent
RECORDS = [
    "civil_asliye_hukuk",
    "labour_is",
    "family_aile",
    "enforcement_icra_hukuk",
    "criminal_agir_ceza",
    "civil_split_labels",
    "consumer_mixed_case",
]


def soffice(txt: pathlib.Path, out_dir: pathlib.Path, profile: pathlib.Path) -> pathlib.Path:
    subprocess.run(
        [
            "soffice",
            f"-env:UserInstallation=file://{profile}",
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(out_dir),
            str(txt),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return out_dir / (txt.stem + ".pdf")


def pages(pdf: pathlib.Path) -> int:
    out = subprocess.run(["pdfinfo", str(pdf)], check=True, capture_output=True, text=True).stdout
    return int(next(l for l in out.splitlines() if l.startswith("Pages:")).split()[1])


# Invented name parts. Combined deterministically; none is meant to be anyone.
GIVEN = ["Taylan", "Sevim", "Orkun", "Nevra", "Kayhan", "Berrin", "Tümay", "İlkay", "Oytun", "Şölen"]
FAMILY = ["KARAYELLİ", "SÖĞÜTÇÜLER", "ILGINKAYA", "DÜZOVALI", "ÇAMLIBELEN", "AKSAZLIOĞLU", "İNCEBURUNLU"]


def long_record(witnesses: int) -> str:
    head, tail = (HERE / "criminal_agir_ceza.txt").read_text().split("GEREĞİ DÜŞÜNÜLDÜ:")
    body = []
    for i in range(witnesses):
        name = f"{GIVEN[i % len(GIVEN)]} {FAMILY[(i * 3) % len(FAMILY)]}"
        body.append(
            f"TANIK : {name}, {GIVEN[(i + 4) % len(GIVEN)]} oğlu, {1960 + i % 40} doğumlu. "
            "Usulen yemini yaptırıldı.\n"
            "Tanık beyanında; olay günü akşam saatlerinde dükkânın önünden geçtiğini, bağırış\n"
            "seslerini duyunca durduğunu, kimseyi tanımadığını, olayın ayrıntısını hatırlamadığını\n"
            "beyan etti. Sorulan sorulara verdiği cevaplarda ilk ifadesindeki beyanlarını tekrar etti.\n"
            "Sanık müdafii: Tanık beyanlarına karşı bir diyeceğimiz yoktur, dedi.\n"
        )
    return head + "\n".join(body) + "\nGEREĞİ DÜŞÜNÜLDÜ:" + tail


def make_long(target: int, work: pathlib.Path, profile: pathlib.Path) -> None:
    # About eleven witness paragraphs fill a page of LibreOffice's default text layout; measure
    # and correct until the page count is exact.
    witnesses = max(1, target * 11 - 8)
    for _ in range(6):
        txt = work / f"long_{target}p.txt"
        txt.write_text(long_record(witnesses))
        pdf = soffice(txt, work, profile)
        got = pages(pdf)
        if got == target:
            shutil.copy(txt, HERE / txt.name)
            shutil.copy(pdf, HERE / pdf.name)
            return
        witnesses += (target - got) * 10 if abs(target - got) > 1 else (target - got) * 3
    sys.exit(f"could not hit {target} pages")


def no_tounicode_pdf() -> bytes:
    """A Type0 font, Identity-H, glyph ids instead of characters, and no ToUnicode."""
    text = (HERE / "civil_asliye_hukuk.txt").read_text().splitlines()[:30]
    glyph = {}
    ops = ["BT", "/F1 10 Tf", "12 TL", "40 800 Td"]
    for line in text:
        cids = "".join(f"{glyph.setdefault(c, len(glyph) + 3):04X}" for c in line)
        ops.append(f"<{cids}> Tj T*")
    ops.append("ET")
    content = "\n".join(ops).encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Subset /Encoding /Identity-H "
        b"/DescendantFonts [6 0 R] >>",
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Subset "
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 600 >>",
    ]
    return assemble(objects)


def bomb_pdf() -> bytes:
    """A page whose one content stream inflates to 32 MiB."""
    raw = b"BT /F1 12 Tf (x) Tj ET\n" + b" " * (32 * 1024 * 1024)
    packed = zlib.compress(raw, 9)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(packed) + packed + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    return assemble(objects)


def assemble(objects: list) -> bytes:
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def gs(args: list) -> None:
    subprocess.run(["gs", "-q", "-dNOPAUSE", "-dBATCH", "-dSAFER", *args], check=True)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        profile = work / "lo-profile"
        for name in RECORDS:
            pdf = soffice(HERE / f"{name}.txt", work, profile)
            shutil.copy(pdf, HERE / pdf.name)
        make_long(5, work, profile)
        make_long(20, work, profile)
        # Over the 40-page cap is built in the test itself (`tests/refusals.rs`, blank pages):
        # half a megabyte of fixture for one refusal was not worth it.

    civil = HERE / "civil_asliye_hukuk.pdf"
    gs(["-sDEVICE=pdfimage8", "-r100", f"-sOutputFile={HERE / 'scan.pdf'}", str(civil)])
    gs(["-sDEVICE=pdfwrite", "-sOwnerPassword=owner-fixture", "-sUserPassword=user-fixture",
        f"-sOutputFile={HERE / 'encrypted_user.pdf'}", str(civil)])
    gs(["-sDEVICE=pdfwrite", "-sOwnerPassword=owner-fixture",
        f"-sOutputFile={HERE / 'encrypted_owner.pdf'}", str(civil)])
    (HERE / "no_tounicode.pdf").write_bytes(no_tounicode_pdf())
    (HERE / "bomb.pdf").write_bytes(bomb_pdf())
    for p in sorted(HERE.glob("*.pdf")):
        print(f"{p.name}: {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
