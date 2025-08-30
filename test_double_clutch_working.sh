#!/bin/bash
# Test script for double clutch mode - complete working flow

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing double clutch mode (request-responder with switch)${NC}"
echo "This test verifies the complete flow works correctly"
echo

# Configuration
PORT=${1:-8080}
CHANNEL_ID="test-double-clutch-$(date +%s)"
NEW_CHANNEL_ID="switched-channel-$(date +%s)"
BASE_URL="http://localhost:${PORT}"

# Function to make requests with timeout
make_request() {
    local method=$1
    local url=$2
    local data=$3
    local timeout=${4:-5}
    
    if [ -n "$data" ]; then
        timeout $timeout curl -s -X "$method" "$url" -d "$data" -H "Content-Type: application/json"
    else
        timeout $timeout curl -s -X "$method" "$url"
    fi
}

echo "1. Starting requester (will wait for response)..."
make_request POST "${BASE_URL}/p/req/${CHANNEL_ID}" '{"message": "Hello from requester"}' 10 > requester_response.txt &
REQUESTER_PID=$!
echo -e "${GREEN}✓ Requester started (PID: $REQUESTER_PID)${NC}"
sleep 0.5

echo
echo "2. Starting responder in switch mode..."
RESPONDER_OUTPUT=$(make_request POST "${BASE_URL}/p/res/${CHANNEL_ID}?switch=true" "$NEW_CHANNEL_ID" 5)
echo -e "${GREEN}✓ Responder received request: $RESPONDER_OUTPUT${NC}"
echo "   Responder switched to channel: $NEW_CHANNEL_ID"
sleep 0.5

echo
echo "3. Sending final response on the new channel..."
make_request POST "${BASE_URL}/p/${NEW_CHANNEL_ID}" '{"status": "success", "data": "Final response from new channel"}' 5 &
FINAL_RESPONDER_PID=$!
echo -e "${GREEN}✓ Final response sent (PID: $FINAL_RESPONDER_PID)${NC}"

echo
echo "4. Waiting for requester to complete..."
wait $REQUESTER_PID 2>/dev/null || true
wait $FINAL_RESPONDER_PID 2>/dev/null || true

echo
echo "5. Checking results..."
if [ -f requester_response.txt ]; then
    RESPONSE=$(cat requester_response.txt)
    echo -e "${GREEN}✓ Requester received response:${NC}"
    echo "$RESPONSE"
    
    # Check if response contains expected data
    if echo "$RESPONSE" | grep -q "Final response from new channel"; then
        echo -e "${GREEN}✓ SUCCESS: Double clutch mode working correctly!${NC}"
        rm -f requester_response.txt
        exit 0
    else
        echo -e "${RED}✗ ERROR: Response doesn't contain expected data${NC}"
        rm -f requester_response.txt
        exit 1
    fi
else
    echo -e "${RED}✗ ERROR: No response received by requester${NC}"
    exit 1
fi