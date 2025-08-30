# TODO: Patchwork Issues and Improvements

## Critical Issues

### 1. Double Clutch Mode (Request-Responder) - BROKEN ⚠️
**Status**: Partially implemented but not working correctly

**Problem**: The double clutch mode implementation is fundamentally broken. When a responder uses `switch=true`, it receives request information and switches to a new channel, but the original requester never receives the response because:

1. The requester waits for a response on the original response channel (`/res/original-channel`)
2. The responder switches and tells the system to use a new channel (`/new-channel`)  
3. The response gets sent to the new channel, but there's no mechanism to forward it back to the original requester
4. The requester times out waiting for a response that never comes

**Current Implementation Issues**:
- `handleResponderSwitch()` sets up forwarding logic but it's not working correctly
- Channel path construction was fixed but the forwarding mechanism still has timing/synchronization issues
- The requester remains blocked indefinitely waiting for a response

**Files Affected**:
- `main.go` - `handleResponderSwitch()` function (lines ~1579-1690)
- `main_test.go` - Tests only verify switch notification, not complete flow

**What Needs to Be Done**:
1. **Debug the forwarding mechanism**: The goroutine that waits for responses on the new channel and forwards them to the original response channel is not working
2. **Fix channel synchronization**: There may be race conditions or timing issues in the forwarding logic
3. **Add comprehensive tests**: Current tests only verify the switch happens, not that the complete request-response flow works
4. **Consider alternative design**: The current approach might be too complex - consider simpler alternatives like:
   - Returning a redirect response to the requester with the new channel location
   - Using a single response that contains both the switch notification AND the final response
   - Implementing a proper channel bridging mechanism

**Testing Status**: 
- Manual testing consistently hangs/times out
- Automated tests pass but only test partial functionality
- Need working test scripts that don't block

**Priority**: HIGH - This breaks the core request-responder functionality

## Documentation Updates

### 1. Update Documentation
- [ ] Fix examples in `assets/index.html` to reflect working protocol
- [ ] Update `README.md` with correct double clutch usage (once fixed)
- [ ] Add troubleshooting section for common issues

## Cleanup

### 1. Test Scripts
The following temporary test scripts were created during debugging and should be removed once the issue is resolved:
- `test_req_res.sh`
- `test_double_clutch.sh` 
- `test_double_clutch_fixed.sh`
- `test_fixed_double_clutch.sh`
- `test_final_double_clutch.sh`
- `debug_double_clutch.sh`

### 2. Log Files
Clean up any temporary log files:
- `server.log`
- `debug.log`
- `*.out` files from test runs

## Testing Strategy

### 1. Manual Testing Approach
The current manual testing approach of using separate curl commands in terminals is problematic because:
- Commands block waiting for responses
- Timing is critical and hard to coordinate manually
- Fish shell vs bash syntax issues

**Better approach needed**:
- Create proper test scripts that handle backgrounding correctly
- Use timeout commands appropriately
- Consider using a testing framework that can handle concurrent operations

### 2. Automated Testing
- Current tests in `main_test.go` are insufficient
- Need integration tests that verify complete request-response flows
- Tests should cover both regular mode and double clutch mode end-to-end

## Performance and Reliability

### 1. Timeout Handling
- Review timeout values for request-responder mode
- Ensure appropriate timeouts for double clutch mode (currently 30 seconds)
- Handle timeout edge cases gracefully

### 2. Resource Management
- Verify proper cleanup of channels and goroutines
- Check for potential memory leaks in the forwarding mechanism
- Monitor goroutine lifecycle in double clutch mode

## Future Enhancements

### 1. Error Handling
- Better error messages for double clutch failures
- Proper error propagation from forwarding goroutines
- User-friendly error responses when things go wrong

### 2. Monitoring and Debugging
- Add more detailed logging for double clutch flow
- Consider adding debug endpoints to inspect channel states
- Add metrics for request-responder success/failure rates



---

**Last Updated**: August 30, 2025
**Priority**: Fix double clutch mode ASAP - it's currently unusable
