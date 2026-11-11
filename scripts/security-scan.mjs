import { spawnSync } from 'node:child_process'
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url))
export const releaseBinaryNames = [
    'hibou-linux-amd64', 'hibou-linux-arm64', 'hibou-windows-amd64.exe',
    'hibou-windows-arm64.exe', 'hibou-darwin-arm64',
]

export function scanSecurity({ root = repositoryRoot, run = spawnSync } = {}) {
    root = resolve(root)
    const binary = join(root, 'dist', 'hibou-linux-amd64')
    if (!lstatSync(binary).isFile()) {
        throw new Error('Expected the built Linux release binary at dist/hibou-linux-amd64')
    }
    const available = new Set(readdirSync(join(root, 'dist')))
    const binaries = releaseBinaryNames.filter(name => available.has(name))
    for (const name of binaries) {
        if (!lstatSync(join(root, 'dist', name)).isFile()) {
            throw new Error(`Expected a regular release binary at dist/${name}`)
        }
    }

    const inputs = mkdtempSync(join(tmpdir(), 'hibou-security-inputs-'))
    try {
        const go = join(inputs, 'go')
        const frontend = join(inputs, 'frontend')
        mkdirSync(go)
        mkdirSync(frontend)
        for (const name of binaries) {
            copyFileSync(join(root, 'dist', name), join(go, name))
        }
        for (const filename of ['package.json', 'package-lock.json']) {
            copyFileSync(join(root, 'site', filename), join(frontend, filename))
        }

        const shared = ['--offline-scan', '--disable-telemetry', '--skip-version-check']
        // rootfs enables Go-binary analysis; fs reads the frontend lockfile.
        const scans = [
            ['rootfs', '--scanners', 'vuln', '--format', 'sarif', '--output', 'trivy-fs.sarif', go],
            ['fs', '--skip-db-update', '--scanners', 'vuln', '--format', 'sarif', '--output', 'trivy-frontend.sarif', frontend],
            ['fs', '--scanners', 'secret', '--format', 'sarif', '--output', 'trivy-secrets.sarif', root],
            ['rootfs', '--skip-db-update', '--format', 'cyclonedx', '--output', 'go-sbom.cdx.json', go],
            ['fs', '--skip-db-update', '--format', 'cyclonedx', '--output', 'frontend-sbom.cdx.json', frontend],
        ]
        for (const args of scans) {
            const result = run('trivy', [args[0], ...shared, ...args.slice(1)], { cwd: root, stdio: 'inherit' })
            if (result.error) {
                throw result.error
            }
            if (result.status !== 0) {
                throw new Error(`Trivy failed for ${args.at(-1)} (${result.signal ?? result.status})`)
            }
        }
    } finally {
        rmSync(inputs, { recursive: true, force: true })
    }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    try {
        scanSecurity()
    } catch (error) {
        console.error(error.message)
        process.exitCode = 1
    }
}
