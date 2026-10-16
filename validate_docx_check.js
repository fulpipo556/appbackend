const fs = require('fs');
const { execFileSync } = require('child_process');

const script = `
import zipfile
content_types = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
document = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hola</w:t></w:r></w:p></w:body></w:document>'
with zipfile.ZipFile('test_valid.docx', 'w', compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr('[Content_Types].xml', content_types)
    z.writestr('word/document.xml', document)
print('created')
`;

execFileSync('python', ['-c', script], { cwd: __dirname, stdio: 'inherit' });

const source = fs.readFileSync('server.js', 'utf8');
const start = source.indexOf('function decodeZipEntryName');
const end = source.indexOf('function extractDocumentBlocks');
const fnText = source.slice(start, end);
const moduleCode = `${fnText}; module.exports = { isValidDocxBuffer };`;
const mod = { exports: {} };
const fn = new Function('module', 'exports', 'Buffer', moduleCode);
fn(mod, mod.exports, Buffer);
const { isValidDocxBuffer } = mod.exports;
const file = fs.readFileSync('test_valid.docx');
console.log('result=' + isValidDocxBuffer(file));
