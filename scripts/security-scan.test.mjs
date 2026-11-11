import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { releaseBinaryNames, scanSecurity } from './security-scan.mjs'

function fixture(t) {
    const root = mkdtempSync(join(tmpdir(), 'hibou-security-scan-test-'))
    t.after(() => rmSync(root, { recursive: true, force: true }))
    for (const directory of ['dist', 'site', 'internal/depinventory/testdata/corpus/maven', 'site/node_modules/unrelated/testdata']) {
        mkdirSync(join(root, directory), { recursive: true })
    }
    writeFileSync(join(root, 'dist/hibou-linux-amd64'), 'synthetic release binary')
    writeFileSync(join(root, 'site/package.json'), '{"name":"example","dependencies":{"vue":"3.5.0"}}')
    writeFileSync(join(root, 'site/package-lock.json'), '{"lockfileVersion":3}')
    writeFileSync(join(root, 'internal/depinventory/testdata/corpus/maven/pom.xml'), '<project>synthetic fixture</project>')
    writeFileSync(join(root, 'site/node_modules/unrelated/testdata/pom.xml'), '<project>unrelated fixture</project>')
    return root
}

test('dependency scans use only the release binary and frontend manifests, while source secrets remain covered', t => {
    const root = fixture(t)
    writeFileSync(join(root, 'dist/hibou-linux-arm64'), 'synthetic arm64 binary')
    writeFileSync(join(root, 'dist/hibou-windows-amd64.exe'), 'synthetic Windows binary')
    writeFileSync(join(root, 'dist/scanner.test'), 'test executable, not a release input')
    const calls = []
    let inputs
    scanSecurity({ root, run(command, args, options) {
        assert.equal(command, 'trivy')
        assert.equal(options.cwd, root)
        assert.ok(args.includes('--offline-scan'))
        assert.ok(args.includes('--disable-telemetry'))
        const target = args.at(-1)
        const output = args[args.indexOf('--output') + 1]
        calls.push({ args, target, output })
        if (output === 'trivy-fs.sarif') {
            assert.equal(args[0], 'rootfs')
            inputs = join(target, '..')
            assert.deepEqual(readdirSync(inputs).sort(), ['frontend', 'go'])
            assert.deepEqual(readdirSync(join(inputs, 'go')).sort(), ['hibou-linux-amd64', 'hibou-linux-arm64', 'hibou-windows-amd64.exe'])
            assert.deepEqual(readdirSync(join(inputs, 'frontend')).sort(), ['package-lock.json', 'package.json'])
            assert.equal(readFileSync(join(inputs, 'go/hibou-linux-amd64'), 'utf8'), 'synthetic release binary')
            assert.equal(readFileSync(join(inputs, 'frontend/package-lock.json'), 'utf8'), '{"lockfileVersion":3}')
            assert.ok(args.includes('vuln'))
        } else if (output === 'trivy-frontend.sarif') {
            assert.equal(args[0], 'fs')
            assert.equal(target, join(inputs, 'frontend'))
            assert.ok(args.includes('vuln'))
        } else if (output === 'trivy-secrets.sarif') {
            assert.equal(args[0], 'fs')
            assert.equal(target, root)
            assert.ok(args.includes('secret'))
            assert.ok(!args.includes('--skip-dirs'), 'do not suppress secrets in test fixtures')
        } else {
            assert.equal(args[0], output.startsWith('go-') ? 'rootfs' : 'fs')
            assert.equal(args[args.indexOf('--format') + 1], 'cyclonedx')
            assert.ok(args.includes('--skip-db-update'))
            assert.equal(target, join(inputs, output.startsWith('go-') ? 'go' : 'frontend'))
        }
        return { status: 0 }
    } })
    assert.equal(calls.length, 5)
    assert.equal(existsSync(inputs), false)
})

test('missing release binaries fail instead of falling back to a checkout scan', t => {
    const root = fixture(t)
    rmSync(join(root, 'dist/hibou-linux-amd64'))
    assert.throws(() => scanSecurity({ root, run() { assert.fail('scanner must not run') } }), /ENOENT/)
})

test('non-regular release inputs are rejected', t => {
    const root = fixture(t)
    rmSync(join(root, 'dist/hibou-linux-amd64'))
    symlinkSync(join(root, 'site/package.json'), join(root, 'dist/hibou-linux-amd64'))
    assert.throws(() => scanSecurity({ root, run() { assert.fail('scanner must not run') } }), /release binary/)
})

test('scan failures are surfaced and temporary inputs are cleaned', t => {
    const root = fixture(t)
    let inputs
    assert.throws(() => scanSecurity({ root, run(_command, args) {
        inputs = args.at(-1)
        return { status: 2 }
    } }), /Trivy failed/)
    assert.equal(existsSync(inputs), false)
})

test('workflow runs the scoped scanner and uploads both vulnerability and secret reports', () => {
    const workflow = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8')
    assert.match(workflow, /node scripts\/security-scan\.mjs/)
    assert.match(workflow, /node --test scripts\/sbom-license\.test\.mjs scripts\/security-scan\.test\.mjs/)
    assert.equal((workflow.match(/^\s+trivy-secrets\.sarif$/gm) ?? []).length, 2)
    assert.equal((workflow.match(/^\s+trivy-frontend\.sarif$/gm) ?? []).length, 2)
    assert.doesNotMatch(workflow, /trivy fs[^\n]*--output go-sbom\.cdx\.json \./)
    const makefile = readFileSync(new URL('../Makefile', import.meta.url), 'utf8')
    const platforms = makefile.match(/^PLATFORMS := (.+)$/m)[1].trim().split(/\s+/)
    assert.deepEqual([...releaseBinaryNames].sort(), platforms.map(platform => `hibou-${platform.replace('/', '-')}${platform.startsWith('windows/') ? '.exe' : ''}`).sort())
})

test('real Trivy keeps fixture Maven packages out while retaining Go and frontend dependencies', t => {
    const repository = fileURLToPath(new URL('../', import.meta.url))
    const binary = process.env.HIBOU_TEST_RELEASE_BINARY ?? join(repository, 'dist/hibou-linux-amd64')
    if (!existsSync(binary)) {
        t.skip('build the release binary first, or set HIBOU_TEST_RELEASE_BINARY')
        return
    }
    if (spawnSync('trivy', ['--version']).error) {
        t.skip('Trivy is not installed')
        return
    }
    const root = fixture(t)
    copyFileSync(binary, join(root, 'dist/hibou-linux-amd64'))
    for (const name of releaseBinaryNames.filter(name => name !== 'hibou-linux-amd64')) {
        const source = join(repository, 'dist', name)
        if (existsSync(source)) copyFileSync(source, join(root, 'dist', name))
    }
    for (const filename of ['package.json', 'package-lock.json']) {
        copyFileSync(join(repository, 'site', filename), join(root, 'site', filename))
    }
    const maven = join(root, 'internal/depinventory/testdata/corpus/maven')
    copyFileSync(join(repository, 'internal/depinventory/testdata/corpus/maven/pom.xml'), join(maven, 'pom.xml'))
    const baseline = join(root, 'fixture.cdx.json')
    const run = (args) => {
        const result = spawnSync('trivy', args, { cwd: root, encoding: 'utf8' })
        assert.equal(result.status, 0, result.stderr)
        return result
    }
    run(['fs', '--offline-scan', '--disable-telemetry', '--skip-version-check', '--skip-db-update', '--skip-java-db-update',
        '--format', 'cyclonedx', '--output', baseline, maven])
    const fixtureDocument = JSON.parse(readFileSync(baseline, 'utf8'))
    assert.ok(fixtureDocument.components.some(component => component.purl === 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2'))

    scanSecurity({ root, run(_command, args) {
        if (args.includes('sarif')) return { status: 0 }
        return run([...args.slice(0, -1), '--skip-java-db-update', args.at(-1)])
    } })
    const go = JSON.parse(readFileSync(join(root, 'go-sbom.cdx.json'), 'utf8'))
    const frontend = JSON.parse(readFileSync(join(root, 'frontend-sbom.cdx.json'), 'utf8'))
    assert.ok(go.components.some(component => component.purl?.startsWith('pkg:golang/github.com/spf13/cobra@')))
    const vue = frontend.components.find(component => component.purl?.startsWith('pkg:npm/vue@'))
    assert.ok(vue)
    assert.ok(vue.licenses?.length, 'retain frontend license evidence from the lockfile')
    assert.ok(go.components.every(component => !component.purl || component.purl.startsWith('pkg:golang/')))
    assert.ok(frontend.components.every(component => !component.purl || component.purl.startsWith('pkg:npm/')))
})
