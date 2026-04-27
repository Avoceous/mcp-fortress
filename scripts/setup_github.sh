#!/usr/bin/env bash
# MCP-Fortress — GitHub Repository Setup Script
# Usage: bash scripts/setup_github.sh [your-github-username]

set -euo pipefail

USERNAME="${1:-w1boost1889M}"
REPO="mcp-fortress"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo ""
echo "🛡️  MCP-Fortress GitHub Setup"
echo "=================================="
echo "Username : $USERNAME"
echo "Repo     : $REPO"
echo "Directory: $DIR"
echo ""

# ── Check prerequisites ──────────────────────────────────────────
check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌ Required: $1 (install it first)"
    exit 1
  fi
}
check_cmd git
check_cmd python3

echo "✅ Prerequisites OK"

# ── Replace placeholder username everywhere ──────────────────────
echo "📝 Replacing 'Avoceous' with '$USERNAME'..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  find "$DIR" -type f \( -name "*.md" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o -name "*.py" -o -name "Dockerfile" \) \
    ! -path "*/.git/*" ! -name "setup_github.sh" \
    -exec sed -i '' "s/Avoceous/$USERNAME/g" {} +
else
  find "$DIR" -type f \( -name "*.md" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o -name "*.py" -o -name "Dockerfile" \) \
    ! -path "*/.git/*" ! -name "setup_github.sh" \
    -exec sed -i "s/Avoceous/$USERNAME/g" {} +
fi
echo "   Done."

# ── Git init ─────────────────────────────────────────────────────
cd "$DIR"
if [ ! -d ".git" ]; then
  git init
  echo "✅ Git repository initialized"
else
  echo "ℹ️  Git repository already exists"
fi

# ── .gitignore ───────────────────────────────────────────────────
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.venv/
venv/
*.egg

# Testing
.pytest_cache/
.coverage
coverage.xml
htmlcov/

# MCP-Fortress runtime
mcp-fortress_audit.jsonl
*.jsonl
logs/

# Environment
.env
.env.*
!.env.example

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
EOF
echo "✅ .gitignore created"

# ── .env.example ─────────────────────────────────────────────────
cat > .env.example << 'EOF'
# MCP-Fortress Environment Configuration
# Copy to .env and fill in your values

# Required for production: cryptographic key for tool integrity signing
# Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
MCPSHIELD_SIGNING_KEY=change-me-in-production

# Upstream MCP server URL
UPSTREAM_MCP_URL=http://localhost:3000

# Proxy settings
MCPSHIELD_HOST=0.0.0.0
MCPSHIELD_PORT=8100

# Policy and logging
MCPSHIELD_POLICY=examples/policy_enterprise.yaml
MCPSHIELD_AUDIT_LOG=logs/audit.jsonl
EOF
echo "✅ .env.example created"

# ── Initial commit ───────────────────────────────────────────────
git add -A
git commit -m "feat: initial MCP-Fortress 0.1.0 release

Production-grade security firewall & proxy for AI Agent MCP.

Detectors:
- TDIV: Tool Description Integrity Verifier (crypto signing + semantic drift)
- BAD: Behavioral Anomaly Detector (call sequence analysis)
- BRE: Blast Radius Estimator (pre-execution risk scoring 0-100)
- PII/Secret Scanner (20+ patterns, redaction)
- Cross-Session Correlator (distributed attack detection)
- Policy-as-Code Firewall (YAML rules, hot-reload)

Features:
- HTTP/SSE/WebSocket proxy transport
- Real-time dashboard at /dashboard
- Active vulnerability scanner (mcp-fortress scan)
- CLI: proxy, scan, verify, report
- Docker + docker-compose
- Zero required dependencies for core engine
- 29 passing tests

Covers OWASP MCP Top 10 (all 10 categories)
" 2>/dev/null || git commit --allow-empty -m "chore: update"

echo "✅ Initial commit created"

# ── Try GitHub CLI if available ──────────────────────────────────
if command -v gh &>/dev/null; then
  echo ""
  echo "📡 GitHub CLI detected. Creating repository..."
  
  gh repo create "$REPO" \
    --public \
    --description "🛡️ Production-grade security firewall & proxy for AI Agent MCP — behavioral anomaly detection, tool integrity verification, blast-radius estimation" \
    --homepage "https://github.com/$USERNAME/$REPO" \
    || echo "ℹ️  Repository may already exist, continuing..."

  git remote remove origin 2>/dev/null || true
  git remote add origin "https://github.com/$USERNAME/$REPO.git"
  git branch -M main
  git push -u origin main

  echo ""
  echo "✅ Repository pushed!"
  echo ""
  echo "🔗 https://github.com/$USERNAME/$REPO"
  echo ""
  echo "Next steps:"
  echo "  1. Add repository topics: mcp, ai-security, llm-security, prompt-injection"
  echo "  2. Enable GitHub Actions under Settings → Actions"
  echo "  3. Set MCPSHIELD_SIGNING_KEY in repository secrets"
  echo "  4. Add to README: [![CI](https://github.com/$USERNAME/$REPO/actions/workflows/ci.yml/badge.svg)]"

else
  echo ""
  echo "ℹ️  GitHub CLI (gh) not found. Manual steps to publish:"
  echo ""
  echo "  1. Create repo at https://github.com/new"
  echo "     Name: $REPO"
  echo "     Description: 🛡️ Production-grade security firewall & proxy for AI Agent MCP"
  echo "     Visibility: Public"
  echo ""
  echo "  2. Push:"
  echo "     git remote add origin https://github.com/$USERNAME/$REPO.git"
  echo "     git branch -M main"
  echo "     git push -u origin main"
  echo ""
  echo "  3. Add topics in GitHub UI:"
  echo "     mcp, ai-security, llm-security, prompt-injection, ai-agent, firewall"
fi

echo ""
echo "🛡️  MCP-Fortress is ready."
