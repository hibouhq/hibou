import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

export const applicationLicense = 'AGPL-3.0-only'

const subjects = {
    go: 'github.com/hibouhq/hibou',
    frontend: '@hibouhq/hibou-ui',
    image: 'github.com/hibouhq/hibou',
}

export function enrichSBOM(document, subject, version) {
    const name = subjects[subject]
    if (!name || !version) {
        throw new Error('Expected subject go, frontend, or image and a nonempty version')
    }
    if (document.bomFormat !== 'CycloneDX' || !document.metadata?.component) {
        throw new Error('Expected a CycloneDX SBOM with metadata.component')
    }
    if (document.components !== undefined && !Array.isArray(document.components)) {
        throw new Error('Expected components to be an array')
    }

    const output = structuredClone(document)
    const licenses = [{ license: { id: applicationLicense } }]
    const application = {
        type: 'application',
        name,
        version,
        'bom-ref': `hibou:application:${subject}`,
        licenses,
    }

    function licenseApplicationComponents(components = []) {
        for (const component of components) {
            if (component.name === name) {
                component.licenses = structuredClone(licenses)
            }
            licenseApplicationComponents(component.components)
        }
    }

    licenseApplicationComponents(output.components)
    if (subject === 'image') {
        output.components ??= []
        const existing = output.components.find(component => component['bom-ref'] === application['bom-ref'])
        if (existing) {
            Object.assign(existing, application)
        } else {
            output.components.push(application)
        }
    } else {
        output.metadata.component = {
            ...output.metadata.component,
            ...application,
            'bom-ref': output.metadata.component['bom-ref'] ?? application['bom-ref'],
        }
    }

    return output
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    try {
        const [file, subject, version] = process.argv.slice(2)
        if (!file) {
            throw new Error('Usage: node scripts/sbom-license.mjs FILE go|frontend|image VERSION')
        }
        const output = enrichSBOM(JSON.parse(readFileSync(file, 'utf8')), subject, version)
        writeFileSync(file, `${JSON.stringify(output, null, 2)}\n`)
        console.log(`${file}: ${subjects[subject]} declared ${applicationLicense}`)
    } catch (error) {
        console.error(error.message)
        process.exitCode = 1
    }
}
