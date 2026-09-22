// Cross-checks the ui.* codes referenced in src/ against catalog.en.json.
// Exits non-zero on codes used but missing from the catalog, and lists
// catalog entries no longer referenced (informational: dynamic families
// like ui.state.{value} are matched by prefix).
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const catalog = JSON.parse(readFileSync(join(root, 'catalog.en.json'), 'utf8'))

function* walk(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f)
    if (statSync(p).isDirectory()) yield* walk(p)
    else if (/\.(tsx?|css)$/.test(f)) yield p
  }
}

const used = new Set()
const families = new Set()
for (const file of walk(join(root, 'src'))) {
  const src = readFileSync(file, 'utf8')
  for (const m of src.matchAll(/family="(ui\.[a-z0-9_.]+)"/g)) families.add(m[1])
  for (const m of src.matchAll(/`(ui\.[a-z0-9_.]+)\.\$\{/g)) families.add(m[1])
  for (const m of src.matchAll(/(?<!family=)['"](ui\.[a-z0-9_.]+)['"]/g)) used.add(m[1])
}

let bad = 0
for (const code of [...used].sort()) {
  if (!(code in catalog)) { console.error(`missing from catalog: ${code}`); bad++ }
}
const unused = Object.keys(catalog).filter((c) => !used.has(c) && ![...families].some((f) => c.startsWith(f + '.')))
if (unused.length) console.log(`catalog entries not referenced directly (dynamic or unused):\n  ${unused.join('\n  ')}`)
console.log(`${used.size} codes referenced, ${Object.keys(catalog).length} in catalog, families: ${[...families].join(', ')}`)
process.exit(bad ? 1 : 0)
