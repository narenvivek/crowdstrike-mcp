# Security Policy

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of our CrowdStrike API integration seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to [your-email@domain.com].

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Security Best Practices

### API Credentials
- Never commit API credentials to the repository
- Use read-only API credentials with minimal required permissions
- Rotate credentials regularly
- Store credentials in environment variables only
- Use `.env` file for local development (and ensure it's in `.gitignore`)

### Code Security
- All API operations are read-only by design
- No sensitive data is stored locally
- Token caching is implemented with proper expiration
- All API responses are properly sanitized
- Input validation is performed on all parameters

### Development Practices
- Keep dependencies updated
- Use virtual environments
- Follow the principle of least privilege
- Monitor API usage and set up alerts
- Regular security audits of the codebase

## Security Updates

Security updates will be released as patch versions (e.g., 1.0.1, 1.0.2) and will be tagged with the `security` label in the release notes.

## Dependencies

We regularly update our dependencies to their latest secure versions. You can find our current dependencies in `requirements.txt`. We recommend:

1. Regularly running `pip install -r requirements.txt --upgrade`
2. Using `pip-audit` to check for known vulnerabilities
3. Monitoring the security advisories of our dependencies

## Security Tools

We recommend using the following tools to ensure the security of your deployment:

- `pip-audit`: For checking Python package vulnerabilities
- `bandit`: For static security analysis
- `safety`: For checking dependencies against known vulnerabilities
- `pyup.io`: For automated security updates

## Responsible Disclosure

We follow a responsible disclosure policy:

1. We will acknowledge receipt of your vulnerability report
2. We will assign a primary handler to investigate your report
3. We will confirm the problem and determine affected versions
4. We will audit code to find any similar problems
5. We will prepare fixes for all supported versions
6. We will coordinate the release of the fix with you

## License

This security policy is licensed under the MIT License - see the LICENSE file for details. 