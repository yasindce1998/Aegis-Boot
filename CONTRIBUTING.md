# Contributing to Barzakh

Thank you for your interest in contributing to the Barzakh project. This document outlines the guidelines and requirements for contributing to this academic research project.

## ⚠️ Important Notice

**Barzakh is a controlled academic research project with strict ethical and legal constraints.** Contributions are limited to authorized personnel who have:

1. ✅ Signed institutional agreements
2. ✅ Completed required ethics training
3. ✅ Been granted explicit access by the Principal Investigator

**If you do not meet these requirements, you cannot contribute to this project.**

## Contribution Eligibility

### Authorized Contributors
- Approved researchers on the project team
- Institutional collaborators with signed agreements
- Peer reviewers during academic publication process (read-only)
- Security researchers with coordinated disclosure agreements

### Prohibited Contributors
- ❌ Contributors outside the institutional framework
- ❌ Anyone seeking to weaponize or misuse the research
- ❌ Contributors who cannot comply with ethical constraints

## Ethical Boundaries

All contributions must adhere to the project's ethical framework:

### ✅ Acceptable Contributions
- Defensive security improvements
- Detection capability enhancements
- Documentation improvements
- Bug fixes that improve safety
- Test coverage improvements
- Academic rigor enhancements

### ❌ Prohibited Contributions
- Weaponization features
- Removal of safety mechanisms
- Bypass of kill-switches
- Data exfiltration capabilities
- Destructive payloads
- 0-day exploitation (outside coordinated disclosure)
- Any feature that violates the project's approved scope

## Contribution Process

### 1. Pre-Contribution Checklist

Before making any contribution:

- [ ] Review the project's ethical guidelines
- [ ] Understand the security constraints
- [ ] Read the technical documentation
- [ ] Set up your development environment per `docs/SETUP.md`

### 2. Development Workflow

```bash
# 1. Create a feature branch
git checkout -b feature/your-feature-name

# 2. Make your changes
# - Follow coding standards
# - Add tests
# - Update documentation

# 3. Sign your commits (REQUIRED)
git commit -S -m "Your commit message"

# 4. Push to your branch
git push origin feature/your-feature-name

# 5. Create a pull request
# - Describe your changes
# - Reference any related issues
# - Explain how changes maintain ethical boundaries
```

### 3. Code Review Process

All contributions undergo rigorous review:

1. **Automated Checks**
   - CI/CD pipeline validation
   - Security constraint verification
   - Build artifact integrity
   - Test suite execution

2. **Peer Review**
   - Code quality assessment
   - Ethical compliance verification
   - Security impact analysis
   - Documentation completeness

3. **Principal Investigator Approval**
   - Final ethical review
   - Merge authorization

## Coding Standards

### General Guidelines

- **Language**: C11 for UEFI code, Python 3.10+ for tooling, Bash for scripts
- **Style**: Follow EDK II coding style for UEFI code
- **Comments**: Clear, concise, and explain *why*, not just *what*
- **Documentation**: Update relevant docs with any changes

### UEFI Code Standards

```c
// Use EDK II types
EFI_STATUS
EFIAPI
MyFunction (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  )
{
  // Function implementation
  return EFI_SUCCESS;
}
```

### Python Code Standards

```python
# Follow PEP 8
# Use type hints
# Include docstrings

def my_function(param: str) -> bool:
    """
    Brief description.
    
    Args:
        param: Parameter description
        
    Returns:
        Return value description
    """
    return True
```

### Bash Script Standards

```bash
#!/bin/bash
# Script description
# Usage: script.sh [OPTIONS]

set -euo pipefail  # Strict error handling

# Use functions
my_function() {
    local param="$1"
    # Implementation
}
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes
- `security`: Security-related changes

**Example:**
```
feat(BootkitPkg): Add PCR validation to DXE hook

Implement TPM PCR validation in the DXE injection module to
ensure attestation data integrity. This enhances the defensive
telemetry capabilities.

Refs: #42
```

### Commit Signing (REQUIRED)

All commits MUST be GPG-signed:

```bash
# Configure GPG signing
git config --global user.signingkey YOUR_GPG_KEY_ID
git config --global commit.gpgsign true

# Sign commits
git commit -S -m "Your message"
```

## Testing Requirements

### Required Tests

All contributions must include:

1. **Unit Tests**: For individual functions/modules
2. **Integration Tests**: For component interactions
3. **Safety Tests**: Verify kill-switches remain functional
4. **Regression Tests**: Ensure existing functionality preserved

### Test Execution

```bash
# Run all tests
./scripts/run-tests.sh

# Run specific test suite
./scripts/run-tests.sh --suite safety

# Run with coverage
./scripts/run-tests.sh --coverage
```

### Test Coverage Requirements

- Minimum 80% code coverage for new code
- 100% coverage for security-critical paths
- All kill-switch mechanisms must have tests

## Documentation Requirements

### Required Documentation Updates

When contributing, update:

1. **Code Comments**: Inline documentation
2. **API Documentation**: For public interfaces
3. **User Documentation**: If user-facing changes
4. **Technical Docs**: For architectural changes
5. **CHANGELOG.md**: Summary of changes

### Documentation Standards

- Use Markdown for all documentation
- Include code examples where appropriate
- Keep language clear and concise
- Update diagrams if architecture changes

## Security Considerations

### Security Review Checklist

Before submitting:

- [ ] No hardcoded secrets or credentials
- [ ] Kill-switches remain functional
- [ ] UUID/TPM binding intact
- [ ] Expiry mechanism preserved
- [ ] No network capabilities added
- [ ] Audit logging maintained
- [ ] SBOM generation works
- [ ] Artifact signing functional

### Vulnerability Disclosure

If you discover a vulnerability:

1. **DO NOT** create a public issue
2. **DO NOT** disclose publicly
3. **DO** notify the Principal Investigator immediately
4. **DO** follow the responsible disclosure process in `SECURITY.md`

## Pull Request Process

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring
- [ ] Security enhancement

## Ethical Compliance
- [ ] Changes maintain all safety mechanisms
- [ ] No weaponization features added
- [ ] Project scope not exceeded
- [ ] Defensive-only purpose maintained

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Safety tests pass
- [ ] Manual testing completed

## Documentation
- [ ] Code comments updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

## Checklist
- [ ] Commits are GPG-signed
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] No merge conflicts
```

### Review Criteria

PRs are evaluated on:

1. **Ethical Compliance**: Maintains project boundaries
2. **Code Quality**: Follows standards and best practices
3. **Security**: Preserves safety mechanisms
4. **Testing**: Adequate test coverage
5. **Documentation**: Complete and accurate
6. **Scope Compliance**: Within approved scope

## Getting Help

### Resources

- **Documentation**: `docs/` directory
- **Setup Guide**: `docs/SETUP.md`
- **Technical Details**: `docs/technical_details.md`
- **Testing Guide**: `docs/testing.md`

### Contact

- **Principal Investigator**: Yasin (yasindce1998@gmail.com)
- **Institution**: Dead Lock Corp

### Communication Channels

- **Issues**: GitHub Issues (for approved contributors only)
- **Discussions**: GitHub Discussions (for approved contributors only)
- **Security**: security@deadlockcorp.edu

## License and Legal

By contributing to this project, you agree that:

1. Your contributions are your original work
2. You have the right to submit the contributions
3. Your contributions will be licensed under the project license
4. You will comply with all ethical and legal constraints
5. You understand the academic research nature of the project

## Enforcement

Violations of these guidelines may result in:

- Contribution rejection
- Access revocation
- Institutional disciplinary action
- Legal consequences (for serious violations)

## Acknowledgments

We appreciate contributions from:

- Project team members
- Institutional collaborators
- Peer reviewers
- Security researchers (coordinated disclosure)

---

**Remember**: This is academic research with real-world security implications. Every contribution must maintain the highest ethical standards and contribute to defensive security knowledge.

**Last Updated**: May 11, 2026  
**Version**: 1.0.0