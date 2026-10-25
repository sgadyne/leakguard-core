"""Bounded, in-memory text extraction; never executes document code or macros."""
import io
import pathlib
import zipfile
import xml.etree.ElementTree as ET

DOCUMENT_SUFFIXES = {'.docx', '.xlsx', '.xlsm', '.pptx', '.pdf', '.msg'}


def extract(data, filename):
    suffix = pathlib.Path(filename).suffix.lower()
    if suffix in {'.docx', '.xlsx', '.xlsm', '.pptx'}:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            total = 0
            for member in archive.infolist():
                if not member.filename.endswith('.xml') or not member.filename.startswith(('word/', 'xl/sharedStrings', 'xl/worksheets/', 'ppt/slides/', 'docProps/')):
                    continue
                if member.file_size > 5_000_000 or total + member.file_size > 12_000_000:
                    raise ValueError('Office XML extraction limit exceeded')
                total += member.file_size
                root = ET.fromstring(archive.read(member))
                text = '\n'.join(value for value in root.itertext() if value.strip())
                yield member.filename, text
    elif suffix == '.pdf':
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise ValueError('Encrypted PDF is not scanned')
        if len(reader.pages) > 300:
            raise ValueError('PDF page limit exceeded')
        total = 0
        for index, page in enumerate(reader.pages, 1):
            text = page.extract_text() or ''
            total += len(text)
            if total > 12_000_000:
                raise ValueError('PDF text extraction limit exceeded')
            if text:
                yield f'page {index}', text
    elif suffix == '.msg':
        import olefile
        with olefile.OleFileIO(io.BytesIO(data)) as message:
            for entry in message.listdir():
                name = entry[-1]
                if name.startswith('__substg1.0_') and name[12:16] in {'1000', '0037', '007D'} and not any(p.startswith('__attach_') for p in entry):
                    text = message.openstream(entry).read().decode('utf-16-le' if name.endswith('001F') else 'cp1252', errors='replace')
                    yield 'message body/headers', text
    else:
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            text = data.decode('utf-16', errors='replace')
        else:
            if b'\x00' in data[:8192]:
                return
            try:
                text = data.decode('utf-8-sig')
            except UnicodeDecodeError:
                return
        yield 'text', text
