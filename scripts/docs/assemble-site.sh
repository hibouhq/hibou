#!/usr/bin/env bash
# Assembles the published site in _site: the landing page at /, each docs
# version under /<version> (plus /stable for releases), versions.json, the
# .hibou.yaml schema and the custom-domain CNAME. _site may already hold the
# previous run's site, which this extends.
# Inputs (env): VERSION, IS_LATEST. Run from the repository root.
set -euo pipefail

mkdir -p _site

# Custom domain for GitHub Pages. This MUST be re-written into the
# artifact on every deploy: Actions-based Pages deployments
# (upload-pages-artifact + deploy-pages) publish a fresh site each run
# and drop the custom domain unless a CNAME file is present in the site
# root. One site: the landing page at /, versioned docs below it.
# The apex serves the site (landing + docs); the Hibou instance
# lives on its own host (dogfood.hibouhq.com), so the static site
# never shares the app's origin.
echo "hibouhq.com" > _site/CNAME

# Copy built docs into version subdirectory
rm -rf "_site/$VERSION"
cp -r docs/dist "_site/$VERSION"

# If this is a tag release, also deploy as "stable"
if [[ "$IS_LATEST" == "false" ]]; then
  rm -rf _site/stable
  cp -r docs/dist _site/stable
fi

# Update versions.json
if [[ -f _site/versions.json ]]; then
  # Add version if not present, ensure latest and stable are first
  jq --arg v "$VERSION" \
    'if (. | index($v)) then . else . + [$v] end' \
    _site/versions.json > _site/versions.tmp
  mv _site/versions.tmp _site/versions.json
else
  echo '["stable", "latest"]' > _site/versions.json
  if [[ "$VERSION" != "latest" && "$VERSION" != "stable" ]]; then
    jq --arg v "$VERSION" '. + [$v]' _site/versions.json > _site/versions.tmp
    mv _site/versions.tmp _site/versions.json
  fi
fi

# Ensure "stable" is always in versions.json
if ! jq -e '. | index("stable")' _site/versions.json > /dev/null 2>&1; then
  jq '. = ["stable"] + .' _site/versions.json > _site/versions.tmp
  mv _site/versions.tmp _site/versions.json
fi

# Root index.html is the landing page; versioned docs live
# under /stable, /latest, /vX.Y. The landing's "Docs" links point to
# ./stable/. Self-contained (assets inlined), so nothing else to copy.
cp docs/landing.html _site/index.html

# The .hibou.yaml schema, at the URL its $id and the generated
# config's yaml-language-server modeline name: editors complete
# and validate .hibou.yaml from it. Unversioned on purpose: the
# schema stays backward compatible within v1.
mkdir -p _site/schemas/v1
cp internal/repoconfig/hibou-config.schema.json _site/schemas/v1/hibou-config.schema.json

echo "Site structure:"
ls -la _site/
