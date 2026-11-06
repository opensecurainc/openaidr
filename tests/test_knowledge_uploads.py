import base64
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from openaidr.server import auth, knowledge, knowledge_retrieval
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_store import db, new_id, tenant
from test_knowledge_retrieval import functional_clock


def document(extension):
    text = 'Orbitctl refresh rebuilds production routing. Use orbitctl inspect to read status.'
    if extension in ('md', 'txt'):
        return text.encode()
    output = io.BytesIO()
    if extension == 'docx':
        from docx import Document
        doc = Document()
        doc.add_paragraph(text)
        doc.add_table(rows=1, cols=1).cell(0, 0).text = 'Production has no fallback.'
        doc.save(output)
    else:
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
        writer = PdfWriter()
        page = writer.add_blank_page(width=600, height=800)
        font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                                 NameObject('/Subtype'): NameObject('/Type1'),
                                 NameObject('/BaseFont'): NameObject('/Helvetica')})
        page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({
            NameObject('/F1'): writer._add_object(font),
        })})
        stream = DecodedStreamObject()
        stream.set_data(('BT /F1 10 Tf 20 750 Td (' + text + ') Tj ET').encode())
        page[NameObject('/Contents')] = writer._add_object(stream)
        writer.write(output)
    return output.getvalue()


def payload(revision=0, filename='operations.md', content=None, keywords=None):
    return {'revision': revision, 'filename': filename,
            'content': base64.b64encode(document('md') if content is None else content).decode(),
            'keywords': ['orbitctl'] if keywords is None else keywords}


def session(db, tid, role):
    user = db.create_user(tid, new_id() + '@test.invalid', role, 'hash', role)
    return db.create_session(user['id'], tid)


@pytest.mark.parametrize('extension', ['md', 'txt', 'pdf', 'docx'])
def test_upload_is_indexed_and_retrievable_with_manual_documents_preserved(db, functional_clock, extension):
    tid = tenant(db)['id']
    legacy = knowledge.update(db, tid, {'revision': 0, 'documents': [{
        'id': 'legacy', 'kind': 'command', 'title': 'Legacy operations', 'keywords': ['legacy'],
        'body': 'Legacy command context remains available.',
    }]}, documents=True)
    cfg = Config(); cfg.set_services('api')
    with TestClient(create_app(cfg, db), headers={auth.CSRF_HEADER: '1'}) as client:
        client.cookies.set(auth.CONSOLE_COOKIE, session(db, tid, 'analyst'))
        result = client.post('/api/v1/knowledge/uploads', json=payload(
            legacy['revision'], 'operations.' + extension, document(extension)))
        assert result.status_code == 200, result.text
        imported = result.json()
        assert 'Orbitctl refresh rebuilds' in imported['passages'][0]['body']
        assert imported['source']['source_type'] == 'upload'
        assert imported['source']['fresh_until'].startswith('9999-')
        library = client.get('/api/v1/knowledge/library').json()
        assert library['retrieval_mode'] == 'postgres' and not library['enabled']
        assert {s['source_type'] for s in library['sources']} == {'manual', 'upload'}
        enabled = client.put('/api/v1/knowledge/library', json={
            'revision': library['revision'], 'enabled': True})
        assert enabled.status_code == 200
        evidence = knowledge_retrieval.retrieve(db, tid, {'kind': 'command', 'command': {'text': 'orbitctl refresh'}})
        assert imported['source']['source_id'] in {doc['source_id'] for doc in evidence['documents']}
        assert evidence['category_coverage']['operation'] != 'exact'
        assert 'Orbitctl refresh' not in json.dumps(db.list_audit(tid)[0], default=str)


def test_upload_access_replacement_revocation_and_invalid_files(db):
    tid, other = tenant(db)['id'], tenant(db)['id']
    cfg = Config(); cfg.set_services('api')
    with TestClient(create_app(cfg, db), headers={auth.CSRF_HEADER: '1'}) as client:
        assert client.post('/api/v1/knowledge/uploads', json=payload()).status_code == 401
        admin = session(db, tid, 'analyst')
        client.cookies.set(auth.CONSOLE_COOKIE, session(db, tid, 'viewer'))
        assert client.post('/api/v1/knowledge/uploads', json=payload()).status_code == 403
        client.cookies.set(auth.CONSOLE_COOKIE, admin)
        assert client.post('/api/v1/knowledge/uploads', headers={auth.CSRF_HEADER: ''}, json=payload()).status_code == 403
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('large.xml', b'x' * (17 << 20))
        for name, content, status in [('x.exe', b'bad', 415), ('x.txt', b'\xff', 400),
                                      ('x.pdf', b'not pdf', 400), ('x.docx', archive.getvalue(), 413),
                                      ('x.txt', b'x' * ((5 << 20) + 1), 413), ('empty.md', b'', 413)]:
            result = client.post('/api/v1/knowledge/uploads', json=payload(filename=name, content=content))
            assert result.status_code == status, result.text
        assert client.get('/api/v1/knowledge/library').json()['revision'] == 0
        first = client.post('/api/v1/knowledge/uploads', json=payload()).json()
        ident = first['source']['source_id']
        assert client.post('/api/v1/knowledge/uploads', json=payload()).status_code == 409
        changed = client.post('/api/v1/knowledge/uploads', json=payload(first['revision'], keywords=['routing']))
        assert changed.status_code == 200, changed.text
        assert changed.json()['source']['source_id'] == ident
        second = changed.json()
        assert second['source']['source_version'] != first['source']['source_version']
        client.cookies.set(auth.CONSOLE_COOKIE, session(db, other, 'analyst'))
        assert client.get('/api/v1/knowledge/sources/' + ident).status_code == 404
        assert client.get('/api/v1/knowledge/library').json()['sources'] == []
        client.cookies.set(auth.CONSOLE_COOKIE, admin)
        removed = client.post('/api/v1/knowledge/sources/' + ident + '/revoke', json={'revision': second['revision']})
        assert removed.status_code == 200, removed.text
        assert removed.json()['passages'] == []
        assert db.scalar('SELECT count(*) FROM knowledge_revisions WHERE tenant_id=$1', tid) == 2
        restored = client.post('/api/v1/knowledge/uploads', json=payload(removed.json()['revision']))
        assert restored.status_code == 200, restored.text
