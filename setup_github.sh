#!/bin/bash
# ============================================================
# Setup script - Run this to push your portfolio to GitHub
# ============================================================

echo "🚀 SOC Portfolio GitHub Setup"
echo "=============================="

# Replace with your info
GITHUB_USERNAME="Ziad-Mohame-Hassan"
REPO_NAME="SOC-Analyst-Portfolio"

echo ""
echo "Step 1: Initialize git"
git init

echo ""
echo "Step 2: Add all files"
git add .

echo ""
echo "Step 3: First commit"
git commit -m "🛡️ Initial SOC Portfolio Structure"

echo ""
echo "Step 4: Set main branch"
git branch -M main

echo ""
echo "Step 5: Add remote (replace YOUR_GITHUB_USERNAME)"
git remote add origin https://github.com/$GITHUB_USERNAME/$REPO_NAME.git

echo ""
echo "Step 6: Push!"
git push -u origin main

echo ""
echo "✅ Done! Check your GitHub: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
