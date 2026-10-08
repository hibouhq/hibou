import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { applicationLicense, enrichSBOM } from './sbom-license.mjs'

test('declarations agree with README, package metadata and final image', () => {
    assert.equal(applicationLicense, 'AGPL-3.0-only')
    const root = new URL('../', import.meta.url)
    const readme = readFileSync(new URL('README.md', root), 'utf8')
    const pkg = JSON.parse(readFileSync(new URL('site/package.json', root)))
    const lock = JSON.parse(readFileSync(new URL('site/package-lock.json', root)))
    assert.match(readme, /version 3 only \(AGPL-3\.0-only\)/)
    assert.equal(pkg.license, applicationLicense)
    assert.equal(lock.packages[''].license, applicationLicense)
    for (const file of ['Dockerfile', 'docker-bake.hcl']) {
        assert.match(readFileSync(new URL(file, root), 'utf8'), /org\.opencontainers\.image\.licenses[^\n]*AGPL-3\.0-only/)
    }
})

function fixture() {
    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        metadata: { component: { type: 'container', name: 'scan-subject', 'bom-ref': 'root' } },
        components: [
            { type: 'library', name: 'vue', 'bom-ref': 'vue', licenses: [{ license: { id: 'MIT' } }] },
            { type: 'library', name: 'ca-certificates', licenses: [{ license: { id: 'MPL-2.0' } }] },
        ],
        dependencies: [{ ref: 'root', dependsOn: ['vue'] }],
    }
}

for (const [subject, name] of [['go', 'github.com/hibouhq/hibou'], ['frontend', '@hibouhq/hibou-ui']]) {
    test(`${subject} declares application subject without changing dependencies`, () => {
        const input = fixture()
        const original = structuredClone(input)
        const output = enrichSBOM(input, subject, 'test-version')
        assert.equal(output.metadata.component.name, name)
        assert.equal(output.metadata.component.type, 'application')
        assert.equal(output.metadata.component.version, 'test-version')
        assert.equal(output.metadata.component['bom-ref'], 'root')
        assert.equal(output.metadata.component.licenses[0].license.id, applicationLicense)
        assert.deepEqual(output.components, original.components)
        assert.deepEqual(output.dependencies, original.dependencies)
        assert.deepEqual(input, original)
        assert.deepEqual(enrichSBOM(output, subject, 'test-version'), output)
    })
}

test('image identifies Hibou without assigning its license to container or base packages', () => {
    const input = fixture()
    const output = enrichSBOM(input, 'image', '1.2.3')
    assert.deepEqual(output.metadata, input.metadata)
    assert.deepEqual(output.components.slice(0, 2), input.components)
    const application = output.components[2]
    assert.equal(application.name, 'github.com/hibouhq/hibou')
    assert.equal(application.licenses[0].license.id, applicationLicense)
    assert.deepEqual(enrichSBOM(output, 'image', '1.2.3'), output)
})

test('corrects own module license while preserving its identity and other components', () => {
    const input = fixture()
    input.components.push({
        type: 'library', name: 'github.com/hibouhq/hibou', 'bom-ref': 'binary-module',
        version: 'v1.2.3', purl: 'pkg:golang/github.com/hibouhq/hibou@v1.2.3',
        licenses: [{ license: { id: 'AGPL-3.0-or-later' } }],
    })
    const output = enrichSBOM(input, 'image', '1.2.3')
    assert.equal(output.components[2]['bom-ref'], 'binary-module')
    assert.equal(output.components[2].purl, input.components[2].purl)
    assert.equal(output.components[2].licenses[0].license.id, applicationLicense)
    assert.deepEqual(output.components[0], input.components[0])
})

test('rejects unsupported input and missing subject/version', () => {
    assert.throws(() => enrichSBOM({}, 'go', '1'), /CycloneDX/)
    assert.throws(() => enrichSBOM(fixture(), 'other', '1'), /Expected subject/)
    assert.throws(() => enrichSBOM(fixture(), 'go', ''), /Expected subject/)
    assert.throws(() => enrichSBOM({ ...fixture(), components: {} }, 'go', '1'), /array/)
})

test('CLI persists application license and leaves invalid input unchanged', () => {
    const directory = mkdtempSync(join(tmpdir(), 'hibou-sbom-license-'))
    try {
        const file = join(directory, 'sbom.json')
        const script = fileURLToPath(new URL('./sbom-license.mjs', import.meta.url))
        writeFileSync(file, JSON.stringify(fixture()))
        const success = spawnSync(process.execPath, [script, file, 'go', 'test-version'])
        assert.equal(success.status, 0, success.stderr.toString())
        assert.equal(JSON.parse(readFileSync(file)).metadata.component.licenses[0].license.id, applicationLicense)
        writeFileSync(file, '{}')
        const failure = spawnSync(process.execPath, [script, file, 'image', '1'])
        assert.equal(failure.status, 1)
        assert.equal(readFileSync(file, 'utf8'), '{}')
    } finally {
        rmSync(directory, { recursive: true, force: true })
    }
})
