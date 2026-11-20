import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const workflow = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8')
const digest = `ghcr.io/hibouhq/hibou-cache@sha256:${'a'.repeat(64)}`

function step(name) {
    const marker = `      - name: ${name}\n`
    const start = workflow.indexOf(marker)
    assert.notEqual(start, -1, `missing workflow step: ${name}`)
    return workflow.slice(start + marker.length).split(/^      - /m)[0]
}

function publish(t, overrides = {}, baseImage = digest) {
    const root = mkdtempSync(join(tmpdir(), 'hibou-ci-image-test-'))
    t.after(() => rmSync(root, { recursive: true, force: true }))
    const bin = join(root, 'bin')
    mkdirSync(bin)
    writeFileSync(join(root, 'apko-base-image.txt'), `${baseImage}\n`)
    for (const command of ['docker', 'git']) {
        const path = join(bin, command)
        writeFileSync(path, `#!${process.execPath}
const { appendFileSync } = require('node:fs')
const args = process.argv.slice(2)
if (${JSON.stringify(command)} === 'git') {
    if (args[0] !== 'tag') process.exit(1)
    process.stdout.write(process.env.TEST_TAGS)
} else {
    const names = ['BASE_IMAGE', 'REPO', 'CACHE_REPO', 'GIT_BRANCH',
        'GIT_TARGET_BRANCH', 'GIT_DEFAULT_BRANCH', 'RELEASE_VERSION',
        'STABLE_RELEASE', 'LATEST', 'SHA_TAG', 'CACHE_PUSH', 'PUSH',
        'INCLUDE_EXTRA_CLI_BINARIES', 'SOURCE_DATE_EPOCH', 'GITHUB_SHA']
    appendFileSync(process.env.TEST_CALLS, JSON.stringify({
        args, env: Object.fromEntries(names.map(name => [name, process.env[name]]))
    }) + '\\n')
}
`)
        chmodSync(path, 0o755)
    }
    const script = step('Build and push image').split('        run: |\n')[1]
    assert.ok(script, 'image publishing must run directly on the host')
    const env = {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        TEST_CALLS: join(root, 'calls.jsonl'),
        TEST_TAGS: 'v1.2.0\nv1.1.0\n',
        REPO: 'HibouHQ/Hibou',
        GITHUB_SHA: '1234567890abcdef',
        GITHUB_EVENT_NAME: 'release',
        GITHUB_REF: 'refs/tags/v1.2.0-alpha.1',
        GIT_BRANCH: 'v1.2.0-alpha.1',
        GIT_TARGET_BRANCH: '',
        GIT_DEFAULT_BRANCH: 'main',
        SOURCE_DATE_EPOCH: '1234567890',
        IS_RELEASE: 'true',
        REF_NAME: 'v1.2.0-alpha.1',
    }
    for (const name of ['BASE_IMAGE', 'CACHE_REPO', 'RELEASE_VERSION', 'STABLE_RELEASE',
        'LATEST', 'SHA_TAG', 'CACHE_PUSH', 'PUSH', 'INCLUDE_EXTRA_CLI_BINARIES']) {
        delete env[name]
    }
    Object.assign(env, overrides)
    const result = spawnSync('bash', ['-c', script.replace(/^ {10}/gm, '')], {
        cwd: root, env, encoding: 'utf8',
    })
    return {
        result,
        calls() {
            return readFileSync(env.TEST_CALLS, 'utf8').trim().split('\n').map(line => JSON.parse(line))
        },
    }
}

function bake(run) {
    assert.equal(run.result.status, 0, run.result.stderr)
    const call = run.calls().find(call => call.args[0] === 'buildx' && call.args[1] === 'bake')
    assert.ok(call, 'must build the image')
    assert.deepEqual(call.args, ['buildx', 'bake', '-f', 'docker-bake.hcl', '--metadata-file', 'bake-metadata.json'])
    assert.equal(call.env.BASE_IMAGE, digest)
    assert.equal(call.env.REPO, 'ghcr.io/hibouhq/hibou')
    assert.equal(call.env.CACHE_REPO, 'ghcr.io/hibouhq/hibou-cache')
    assert.equal(call.env.PUSH, 'true')
    assert.equal(call.env.SOURCE_DATE_EPOCH, '1234567890')
    assert.equal(call.env.GITHUB_SHA, '1234567890abcdef')
    return call.env
}

test('base image stays in the devcontainer; runtime publishing uses host Docker without DinD', () => {
    const base = step('Publish base image')
    assert.match(base, /uses: \.\/\.github\/actions\/devcontainer-ci/)
    assert.match(base, /if: github\.event_name != 'pull_request'/)
    assert.match(base, /apko publish --lockfile apko\.lock\.json/)
    assert.match(base, /printf '%s\\n' "\$\{BASE_IMAGE\}" > apko-base-image\.txt/)
    const image = step('Build and push image')
    assert.match(image, /if: github\.event_name != 'pull_request'/)
    assert.doesNotMatch(image, /uses:|docker-init|sudo|apko publish|GITHUB_TOKEN/)
    assert.match(workflow, /node --test scripts\/ci-image\.test\.mjs/)
    assert.ok(workflow.indexOf('- name: Log in to GHCR') < workflow.indexOf('- name: Build and push image'))
    assert.ok(workflow.indexOf('- name: Publish base image') < workflow.indexOf('- name: Build and push image'))
})

test('prereleases publish version tags without stable tags or cache writes', t => {
    const env = bake(publish(t))
    assert.equal(env.RELEASE_VERSION, '1.2.0-alpha.1')
    assert.equal(env.STABLE_RELEASE, undefined)
    assert.equal(env.LATEST, undefined)
    assert.equal(env.SHA_TAG, '')
    assert.equal(env.CACHE_PUSH, 'false')
    assert.equal(env.INCLUDE_EXTRA_CLI_BINARIES, 'true')
})

test('newest stable release retains latest and stable tagging', t => {
    const env = bake(publish(t, { REF_NAME: 'v1.2.0' }))
    assert.equal(env.RELEASE_VERSION, '1.2.0')
    assert.equal(env.STABLE_RELEASE, 'true')
    assert.equal(env.LATEST, 'true')
    assert.equal(env.CACHE_PUSH, 'false')
})

test('older stable release does not overwrite latest', t => {
    const env = bake(publish(t, { REF_NAME: 'v1.1.0' }))
    assert.equal(env.STABLE_RELEASE, 'true')
    assert.equal(env.LATEST, undefined)
})

test('exact main push retains SHA tags, cache writes, and Linux-only CLI binaries', t => {
    const env = bake(publish(t, {
        GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main',
        GIT_BRANCH: 'main', IS_RELEASE: 'false', REF_NAME: 'main',
    }))
    assert.equal(env.SHA_TAG, 'sha-1234567')
    assert.equal(env.CACHE_PUSH, 'true')
    assert.equal(env.RELEASE_VERSION, undefined)
    assert.equal(env.INCLUDE_EXTRA_CLI_BINARIES, 'false')
})

test('a similarly named branch never writes main tags or cache', t => {
    const env = bake(publish(t, {
        GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main/other',
        GIT_BRANCH: 'main/other', IS_RELEASE: 'false',
    }))
    assert.equal(env.CACHE_PUSH, 'false')
    assert.equal(env.SHA_TAG, '')
    assert.equal(env.GIT_BRANCH, 'main-other')
})

test('unapproved or mutable base image references fail before invoking Docker', t => {
    for (const ref of ['ghcr.io/hibouhq/hibou-cache:apko-base',
        `ghcr.io/other/image@sha256:${'a'.repeat(64)}`, `${digest}\nextra`]) {
        const run = publish(t, {}, ref)
        assert.notEqual(run.result.status, 0)
        assert.match(run.result.stdout + run.result.stderr, /digest reference/)
        assert.throws(run.calls, /ENOENT/)
    }
})
