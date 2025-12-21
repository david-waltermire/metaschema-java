# Development Workflow

## Skill Usage Protocol (MANDATORY)

Before responding to ANY task, complete this checklist:

1. **Check for relevant skills** - Does any skill match this request?
2. **If skill exists** → Use `Skill` tool to load and run it
3. **Announce usage** - "I'm using [skill] to [action]"
4. **Follow skill exactly** - Don't adapt away the discipline

### Checklist Tracking Rule
If a skill has a checklist, create **TodoWrite todos for EACH item**. Never:
- Work through checklists mentally
- Skip todos "to save time"
- Batch multiple items into one todo

### Common Rationalizations (RED FLAGS)
If you think any of these, STOP and check for skills:
- "This is just a simple question"
- "Let me gather information first"
- "This doesn't need a formal skill"
- "The skill is overkill for this"
- "I'll just do this one thing first"

**Why:** Skills document proven techniques. Not using available skills = repeating solved problems.

### Available Skills

**Project Skills** (defined in `.claude/skills/`):
- `prd-construction` - Templates and methodology for creating PRDs and implementation plans

**Managed Skills** (from superpowers plugin - install via `claude plugin add superpowers-marketplace`):
- `superpowers:brainstorming` - Refine ideas into designs through collaborative questioning
- `superpowers:writing-plans` - Create detailed implementation plans
- `superpowers:executing-plans` - Execute tasks in batches with review checkpoints
- `superpowers:test-driven-development` - Write tests first, then implementation
- `superpowers:subagent-driven-development` - Quality-gated autonomous work
- `superpowers:dispatching-parallel-agents` - Concurrent work on independent tasks
- `superpowers:systematic-debugging` - 4-phase debugging framework
- `superpowers:root-cause-tracing` - Trace bugs backward to find source
- `superpowers:verification-before-completion` - Confirm work is complete
- `superpowers:requesting-code-review` - Review implementation against plan
- `superpowers:testing-anti-patterns` - Avoid common testing mistakes

### Instructions ≠ Permission to Skip Workflows
User instructions describe WHAT to do, not HOW. "Add X" or "Fix Y" does NOT mean skip brainstorming, TDD, or verification workflows.

---

## PRD-Based Development Lifecycle

For new development work, follow this structured lifecycle:

### Phase 1: PRD Development
1. **Use `superpowers:brainstorming`** to refine requirements
2. **Use `prd-construction` skill** for templates and methodology
3. **Create PRD directory**: `PRDs/[date]-[name]/` (see `prd-conventions.md` for naming)
4. **Create PRD documents** using skill templates:
   - `PRD.md` - Problem statement, goals, requirements, success metrics
   - `implementation-plan.md` - Detailed PR breakdown with acceptance criteria
5. **Add supporting documents** to the directory as needed (analysis, research, diagrams)

### PRD Directory Structure
```text
PRDs/[date]-[name]/
├── PRD.md                 # Main requirements document
├── implementation-plan.md # Detailed PR breakdown
└── [supporting-docs].md   # Analysis, research, etc.
```

### Phase 2: User Approval
- Present PRD to user for review
- Incorporate feedback and iterate
- **Do NOT proceed to development until PRD is approved**

### Phase 3: Development
Execute the plan using these skills:
- `superpowers:executing-plans` - Execute tasks in batches with review checkpoints
- `superpowers:test-driven-development` - Write tests first, then implementation
- `superpowers:subagent-driven-development` - Quality-gated autonomous work
- `superpowers:dispatching-parallel-agents` - Concurrent work on independent tasks

**Auto-applied skills** (Claude automatically uses these when relevant):
- `superpowers:testing-anti-patterns` - Avoid testing mock behavior, test-only production methods

**Update PRD documents as you work:**
- Mark acceptance criteria as `[x]` when completed
- Update PR status in implementation-plan.md
- Add notes about deviations from plan

### Phase 4: Code Review Cycle
Perform iterative code review until all issues are resolved:

1. **Run code review agents** (can run multiple in parallel):
   - `superpowers:requesting-code-review` - Review implementation against plan

2. **Consolidate review findings** into a report of identified issues

3. **Work the issues**:
   - Address each identified issue
   - Apply `superpowers:test-driven-development` for any gaps found

4. **Re-review** - Run code review again on changes

5. **Repeat** until all issues are resolved and changes are accepted

```
Code Complete
    ↓
Code Review Agents (parallel) → Consolidated Issues Report
    ↓
Work Issues → Re-review
    ↓
[Issues Found?] → Yes → Work Issues → Re-review
    ↓
No Issues → Proceed to Verification
```

### Phase 5: Verification & PR
- `superpowers:verification-before-completion` - Confirm all tests pass
- Verify all code review issues are resolved
- Create PR against `develop` branch
- Always use squash merge with branch deletion (`gh pr merge --squash --delete-branch`)

### Build Verification Summary Format

After running builds with quality checks, provide a scannable summary:

```text
Build verified successfully:
- ✅ Tests: 56 passed, 0 failed
- ✅ SpotBugs: 0 bugs, 0 errors
- ✅ PMD: 0 violations, 97 warnings
- ✅ Checkstyle: 0 violations, 5 warnings
```

**Guidelines:**
- Use ✅ for passing checks (no blocking errors/violations), ❌ for failures
- Always report both errors/violations AND warnings for each tool
- Add brief context for notable items (e.g., "import order fixed")
- Report failures clearly so they can be addressed before proceeding

**Example with failures:**
```text
Build failed:
- ✅ Tests: 54 passed, 2 failed
- ❌ SpotBugs: 2 bugs (null pointer issues), 0 errors
- ✅ PMD: 0 violations, 45 warnings
- ❌ Checkstyle: 3 violations (missing Javadoc), 12 warnings
```

### Workflow Summary
```
GitHub issue/prompt
    ↓
brainstorming → prd-construction → PRDs/[date]-[name]/
    ↓
User Approves PRD
    ↓
executing-plans + TDD + subagents
    ↓
Update implementation-plan.md with progress [x]
    ↓
verification-before-completion
    ↓
PR to develop
```

---

## Debugging Workflow

When debugging issues (during development or in production):

### Step 1: Identify Root Cause (REQUIRED)
**Do NOT attempt fixes until root cause is identified.**

Use these skills:
- `superpowers:systematic-debugging` - 4-phase framework: investigation → pattern analysis → hypothesis testing → implementation
- `superpowers:root-cause-tracing` - Trace bugs backward through call stack to find the source

**Root cause identification must include:**
- What is the actual vs expected behavior?
- Where in the code does the bug originate?
- Why does this code path produce the wrong result?

**Post Bug Reproduction comment to Jira** (see Jira Comments section below)

### Step 2: Verify Test Coverage
Once root cause is confirmed:
1. **Check for existing test** - Does a test cover this scenario?
2. **If no test exists** - Use `superpowers:test-driven-development` to:
   - Write a failing test that reproduces the bug
   - Confirm the test fails for the right reason
   - Do NOT proceed to fix until test fails correctly

### Step 3: Implement Fix
- Fix the identified root cause
- Run the failing test - it should now pass
- Run all related tests

### Step 4: Code Review Cycle
1. **Run code review agents** (parallel) on the fix
2. **Consolidate issues** into a report
3. **Work issues** and re-review
4. **Repeat** until all issues resolved

### Step 5: Verification & PR
- Use `superpowers:verification-before-completion` before claiming fixed
- Confirm all tests pass
- Verify all code review issues are resolved
- Create PR against `develop` branch

### Debugging Summary
```
Bug Report / Issue
    ↓
systematic-debugging + root-cause-tracing
    ↓
ROOT CAUSE IDENTIFIED (required before proceeding)
    ↓
Check Test Coverage
    ↓
[No Test?] → test-driven-development → Write Failing Test
    ↓
Implement Fix (target the root cause)
    ↓
verification-before-completion
    ↓
PR to staging
```

---

## Testing Best Practices

When writing or modifying tests, apply `superpowers:testing-anti-patterns`:

### Iron Laws
1. **NEVER test mock behavior** - Assert on real component behavior, not mock existence
2. **NEVER add test-only methods to production classes** - Put test utilities in test files
3. **NEVER mock without understanding dependencies** - Know what side effects tests depend on

### Gate Functions (Ask Before Each Action)

**Before asserting on mocks:**
> "Am I testing real behavior or just mock existence?"
> If testing mock existence → Delete assertion or unmock component

**Before adding methods to production classes:**
> "Is this only used by tests?"
> If yes → Put in test utilities instead

**Before mocking any method:**
> "What side effects does this have? Does my test depend on them?"
> If test depends on side effects → Mock at lower level, not the method test needs

### Quick Reference

| Anti-Pattern | Fix |
|--------------|-----|
| Assert on mock elements | Test real component or unmock |
| Test-only methods in production | Move to test utilities |
| Mock without understanding | Understand deps first, mock minimally |
| Incomplete mocks | Mirror real API completely |
| Tests as afterthought | TDD - tests first |

### Red Flags
- Assertions checking for `*-mock` test IDs
- Methods only called in test files
- Mock setup is >50% of test code
- Test fails when you remove mock
- Mocking "just to be safe"

---

## When to Use PRD Workflow
- New features
- Significant refactoring
- Complex bug fixes requiring architectural changes

## When to Skip PRD
- Simple bug fixes with clear solutions
- Minor UI tweaks
- Minor documentation updates
