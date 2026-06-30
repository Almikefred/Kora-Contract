#!/usr/bin/env bash
# =============================================================================
# Kora Protocol — End-to-End Reference Demo
#
# Walks through every step of the README "How It Works" diagram:
#
#   SME mints invoice → marketplace lists it → investors fund it →
#   funds released to SME → SME repays → investors receive yield →
#   (optional) admin marks defaulted invoice
#
# This is the canonical first script a new contributor should run to see
# the full protocol flow against a live deployment.
#
# Usage:
#   export DEPLOYER_SECRET="your-stellar-secret"
#   export ADMIN_ADDRESS="G..."
#   export VERIFIER_ADDRESS="G..."
#   export SME_ADDRESS="G..."
#   export INVESTOR_A="G..."
#   export INVESTOR_B="G..."
#   export USDC_TOKEN="C..."        # whitelisted stablecoin contract address
#   bash scripts/demo.sh testnet    # defaults to testnet
#
# Prerequisites: stellar CLI >= 20.0.0, jq, a deployment manifest from deploy.sh
# =============================================================================

set -euo pipefail

NETWORK="${1:-testnet}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Validate required env vars ────────────────────────────────────────────────
for var in DEPLOYER_SECRET ADMIN_ADDRESS VERIFIER_ADDRESS SME_ADDRESS INVESTOR_A INVESTOR_B USDC_TOKEN; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: \$$var is not set." >&2
    echo ""
    echo "Usage:"
    echo "  export DEPLOYER_SECRET=... ADMIN_ADDRESS=... VERIFIER_ADDRESS=..."
    echo "  export SME_ADDRESS=... INVESTOR_A=... INVESTOR_B=... USDC_TOKEN=..."
    echo "  bash scripts/demo.sh [testnet|mainnet]"
    exit 1
  fi
done

# ── Load interact.sh helpers (sets kora_* functions + contract addresses) ────
# shellcheck source=scripts/interact.sh
source "$SCRIPT_DIR/interact.sh" "$NETWORK"

# ── Demo parameters ───────────────────────────────────────────────────────────
# SHA-256 hash of debtor PII — actual PII lives off-chain on IPFS.
DEBTOR_HASH="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

# Face value: 10,000 USDC expressed in stroops (7 decimals).
FACE_VALUE=10000000000

# Asking price: 9,500 USDC (5% discount — the investor's yield).
ASKING_PRICE=9500000000

# Two investors split the asking price 50/50.
INV_A_AMOUNT=4750000000
INV_B_AMOUNT=4750000000

# IPFS CID pointing to the full invoice metadata document.
IPFS_CID="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

# Risk score 0–100; 30 = AA tier (low risk).
RISK_SCORE=30

# Due date: 60 days from now.
DUE_DATE=$(( $(date +%s) + 86400 * 60 ))

# Funding deadline: 30 days from now.
FUNDING_DEADLINE=$(( $(date +%s) + 86400 * 30 ))

# ── Helper ────────────────────────────────────────────────────────────────────
step() { echo ""; echo "══════════════════════════════════════════════"; echo "  STEP $1: $2"; echo "══════════════════════════════════════════════"; }

# =============================================================================
# STEP 1 — Register a verifier and onboard the SME
#
# The risk_registry tracks which SMEs are approved to mint invoices.
# A verifier (e.g. a KYC provider) must be authorised by the admin first.
# =============================================================================
step 1 "Register verifier & onboard SME"

echo "→ Authorising verifier..."
kora_add_verifier "$ADMIN_ADDRESS" "$VERIFIER_ADDRESS"

echo "→ Registering SME with risk score $RISK_SCORE..."
kora_register_sme "$VERIFIER_ADDRESS" "$SME_ADDRESS" "$RISK_SCORE"

echo "→ Querying SME profile..."
kora_get_sme_profile "$SME_ADDRESS"

# =============================================================================
# STEP 2 — SME mints an invoice NFT
#
# The invoice is stored on-chain as an NFT. Sensitive debtor information
# (name, address) is hashed — the full details live on IPFS (ipfs_cid).
# Status transitions from: Created → Listed → Funded → Repaid | Defaulted
# =============================================================================
step 2 "SME mints invoice NFT"

echo "→ Minting invoice (face value $FACE_VALUE stroops, due $(date -d @$DUE_DATE))..."
INVOICE_ID=$(kora_mint_invoice \
  "$SME_ADDRESS" \
  "$DEBTOR_HASH" \
  "$FACE_VALUE" \
  "USDC" \
  "$DUE_DATE" \
  "$IPFS_CID" \
  "$RISK_SCORE")

echo "✓ Invoice minted with ID: $INVOICE_ID"
echo "→ Querying invoice state..."
kora_get_invoice "$INVOICE_ID"

# =============================================================================
# STEP 3 — SME lists the invoice on the marketplace
#
# The SME sets a discounted asking price (investors pay 9,500 USDC for a
# 10,000 USDC invoice). The spread is the investor's return at repayment.
# A funding deadline prevents listings from sitting open indefinitely.
# =============================================================================
step 3 "List invoice on marketplace (asking $ASKING_PRICE stroops)"

kora_list_invoice \
  "$SME_ADDRESS" \
  "$INVOICE_ID" \
  "$ASKING_PRICE" \
  "$FACE_VALUE" \
  "$USDC_TOKEN" \
  "$FUNDING_DEADLINE"

echo "✓ Invoice listed. Status should now be 'Listed'."
kora_get_invoice "$INVOICE_ID"

# =============================================================================
# STEP 4 — Two investors fund the invoice
#
# Partial funding is supported. The marketplace collects a protocol fee
# (50 bps by default) on each contribution. Once the asking price is
# fully covered, the financing_pool automatically releases net proceeds
# to the SME.
# =============================================================================
step 4 "Investors fund the invoice"

echo "→ Investor A contributing $INV_A_AMOUNT stroops..."
kora_fund_invoice "$INVESTOR_A" "$INVOICE_ID" "$INV_A_AMOUNT"

echo "→ Investor B contributing $INV_B_AMOUNT stroops..."
kora_fund_invoice "$INVESTOR_B" "$INVOICE_ID" "$INV_B_AMOUNT"

echo "✓ Invoice fully funded. Status should now be 'Funded'. SME received net proceeds."
kora_get_invoice "$INVOICE_ID"
kora_get_pool "$INVOICE_ID"

# =============================================================================
# STEP 5 — SME repays the face value
#
# On or before the due date, the SME repays the full face value (10,000 USDC).
# The financing_pool distributes principal + yield to each investor in
# proportion to their contribution. The spread (500 USDC) is the yield.
# =============================================================================
step 5 "SME repays face value ($FACE_VALUE stroops)"

kora_repay "$SME_ADDRESS" "$INVOICE_ID" "$USDC_TOKEN" "$FACE_VALUE"

echo "✓ Repayment complete. Status should now be 'Repaid'."
kora_get_invoice "$INVOICE_ID"
kora_get_pool "$INVOICE_ID"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Happy path complete! Investors received      ║"
echo "║  principal + yield. Protocol flow verified.   ║"
echo "╚══════════════════════════════════════════════╝"

# =============================================================================
# DEFAULT PATH (optional — separate invoice)
#
# Uncomment the block below to demonstrate the default/recovery flow:
# a second invoice is minted, funded, and then the SME fails to repay.
# The admin marks it defaulted after the due date, triggering partial
# recovery distribution to investors.
#
# Run with: DEMO_DEFAULT=1 bash scripts/demo.sh testnet
# =============================================================================
if [ "${DEMO_DEFAULT:-0}" = "1" ]; then
  step 6 "Default scenario (DEMO_DEFAULT=1)"

  # Short due date: 2 minutes from now so we can advance past it in testing.
  SHORT_DUE=$(( $(date +%s) + 120 ))
  SHORT_DEADLINE=$(( $(date +%s) + 60 ))

  echo "→ Minting a second invoice with a near-term due date..."
  INVOICE2=$(kora_mint_invoice \
    "$SME_ADDRESS" \
    "$DEBTOR_HASH" \
    "$FACE_VALUE" \
    "USDC" \
    "$SHORT_DUE" \
    "$IPFS_CID" \
    "$RISK_SCORE")

  echo "✓ Invoice $INVOICE2 minted"

  kora_list_invoice \
    "$SME_ADDRESS" \
    "$INVOICE2" \
    "$ASKING_PRICE" \
    "$FACE_VALUE" \
    "$USDC_TOKEN" \
    "$SHORT_DEADLINE"

  kora_fund_invoice "$INVESTOR_A" "$INVOICE2" "$INV_A_AMOUNT"
  kora_fund_invoice "$INVESTOR_B" "$INVOICE2" "$INV_B_AMOUNT"

  echo "→ Waiting for due date to pass (120 s)..."
  sleep 125

  # Admin marks the invoice as defaulted. This distributes any partial
  # recovery pro-rata to investors and increments the SME's default count
  # in the risk_registry.
  echo "→ Admin marking invoice $INVOICE2 as defaulted..."
  stellar contract invoke \
    --id "$INVOICE_NFT" \
    --source-account "$DEPLOYER_SECRET" \
    --rpc-url "$RPC_URL" \
    --network-passphrase "$NETWORK_PASSPHRASE" \
    -- set_defaulted \
    --caller "$ADMIN_ADDRESS" \
    --invoice_id "$INVOICE2"

  echo "✓ Invoice $INVOICE2 defaulted."
  kora_get_invoice "$INVOICE2"
  kora_get_sme_profile "$SME_ADDRESS"
fi

echo ""
echo "Demo complete."
