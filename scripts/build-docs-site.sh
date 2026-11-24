#!/usr/bin/env bash
# Build the rustdoc API site into _site/ (served at https://joshlacal.github.io/catbird-mls/).
# Run from anywhere; sibling repos referenced by path dependencies must sit next to this repo.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export CMAKE_POLICY_VERSION_MINIMUM="${CMAKE_POLICY_VERSION_MINIMUM:-3.5}"

rm -rf _site target/doc
cargo doc --no-deps --locked --features labyrinth,legacy-orchestrator,fork-resolution
test -f "target/doc/catbird_mls/index.html"
mkdir -p _site
cp -R target/doc/. _site/
touch _site/.nojekyll
cat > _site/index.html <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>catbird-mls API documentation</title>
<link rel="canonical" href="catbird_mls/index.html">
<meta http-equiv="refresh" content="0; url=catbird_mls/index.html">
</head>
<body>
<p><a href="catbird_mls/index.html">catbird-mls API documentation</a></p>
</body>
</html>
HTML
echo "Docs site ready: _site/catbird_mls/index.html"
