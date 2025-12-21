# Unit Testing Standards

## Core Principles

### What NOT to Test

**Never test trivial code:**
- Getters and setters (no logic = no test)
- Simple constructors that only assign fields
- Delegation methods that just call another method
- Framework-generated code (Lombok, records, etc.)

**Why:** Tests should verify behavior, not structure. Trivial tests add maintenance burden without catching bugs.

### What TO Test

**Always test:**
- Business logic and calculations
- Validation and error handling
- State changes and side effects
- Integration points and boundaries
- Edge cases and corner cases

### Prioritize Edge Cases

Every test class should prioritize edge case coverage over happy paths:

- **Boundary conditions** - empty collections, null inputs, zero values, max values
- **Error paths** - invalid inputs, missing required data, exception scenarios
- **State transitions** - before/after states, partial completion, rollback scenarios
- **Combinations** - multiple flags, conflicting options, compound conditions

## Mandatory Coverage Evaluation

**When modifying existing code, you MUST evaluate and expand test coverage.**

1. Check if tests exist for the code path you're touching
2. Identify missing edge cases
3. Add tests before completing the work

Use the `unit-test-writing` skill for the detailed workflow.
