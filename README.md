# CrowdStrike API Integration

This project provides a Python-based integration with the CrowdStrike Falcon API, offering a comprehensive set of tools for retrieving security-related information. The integration is designed to be read-only, focusing on data retrieval and analysis.

> **Important Note**: This integration is currently only tested on Mac OSX. While it may work on Windows, it has not been thoroughly tested. Linux support is planned for future releases.

## Security First

This project follows security best practices:
- No sensitive data is stored in the repository
- All credentials are managed through environment variables
- Example files use dummy data only
- Comprehensive `.gitignore` to prevent accidental commits of sensitive files
- Example files are stored in the `examples/` directory

## Claude AI and Model Context Protocol (MCP) Integration

This project is designed to work seamlessly with Claude AI through the Model Context Protocol (MCP), enabling powerful AI-assisted security analysis. The integration allows Claude to:

- Access real-time security data from CrowdStrike
- Analyze security incidents and detections
- Provide contextual insights about threats
- Assist in security investigations
- Generate detailed security reports

To use this integration with Claude AI, please refer to the official MCP documentation at [modelcontextprotocol.io](https://modelcontextprotocol.io/quickstart/user) for setup instructions.

### Sample AI-Generated Security Report

Here's an example of how Claude AI can analyze CrowdStrike data to generate comprehensive security reports. Note that all sensitive information (hostnames, IPs, indicators) has been replaced with dummy data for demonstration purposes:

```markdown
# DAIR Methodology: Incident Response Plan for Recent Security Incidents

## Phase 1: Detection & Analysis

### 1. Situational Assessment
- **Current Status**: Active security incident on SRV-PROD-001 with multiple high-severity detections
- **Incident Timeline**: Detections began today at 15:32 UTC and are continuing
- **Priority Classification**: Critical - active threat in progress
- **Affected Systems**: 
  - Primary: SRV-PROD-001 (192.168.1.100)
  - Secondary: SRV-PROD-002 (192.168.1.101)
  - Suspicious IP: 203.0.113.42

### 2. Form Dynamic Response Team
- **Core Team**: Security analyst, system administrator, network administrator
- **Extended Team**: IT management, legal counsel, communications representative
- **Subject Matter Experts**: Threat specialist, system expert

### 3. Establish Communication Channels
- Create dedicated incident communication channel (#incident-response-2024-05)
- Schedule regular status updates
- Define escalation paths and emergency contacts

## Phase 2: Immediate Containment

### 1. Network Isolation
- **Immediately disconnect affected systems from the network**
  - Use network controls to block all traffic to/from 203.0.113.42
  - If physical access is available, disconnect network cables
  - Document exact time of isolation

### 2. Execute Real-Time Response (RTR)
- Initiate RTR session to SRV-PROD-001
- Collect volatile evidence:
  - Running processes (`ps`)
  - Network connections (`netstat -ano`)
  - Active users (`who`)
  - Command history

### 3. Preserve Evidence
- Capture memory dump if system is operational
- Document all observed indicators:
  - Suspicious file: `C:\Windows\Temp\svchost.exe` (SHA256: a1b2c3d4...)
  - Malicious process: `rundll32.exe` (PID: 1234)
  - Registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\UpdateService`
- Begin chain-of-custody documentation

## Phase 3: Dynamic Investigation

### 1. Scope Determination
- **Check all domain controllers for signs of compromise**
  - Focus on authentication logs
  - Look for unusual lateral movement
  - Monitor privileged account usage
  - Check DC-01 and DC-02 for suspicious activities

### 2. Attack Vector Analysis
- Review inbound connections to SRV-PROD-001
- Check email logs for phishing campaigns
- Examine VPN/remote access logs for suspicious logins
- Review recent changes or updates to the affected system

### 3. Threat Identification
- Analyze file patterns and extensions
- Examine any threat indicators
- Match behaviors to known threat variants
- Use IOCs from recent detections:
  - File hash: a1b2c3d4...
  - IP address: 203.0.113.42
  - Domain: malicious-domain[.]com

## Phase 4: Eradication & Recovery

### 1. Clean System Restoration
- Identify clean backups
- Prepare fresh OS installation
- Restore from validated backups

### 2. Vulnerability Remediation
- Address exploited vulnerabilities
- Apply security patches
- Implement additional security controls

### 3. Service Restoration
- Restore critical services
- Implement enhanced monitoring
- Conduct security validation
- Perform staged reconnection

## Phase 5: Continuous Improvement

### 1. Process Enhancement
- Review incident detection performance
- Improve alert visibility
- Implement response automation

### 2. Security Posture Strengthening
- Implement regular vulnerability scanning
- Review network segmentation
- Enhance backup strategies
- Develop specific response playbooks

### 3. Knowledge Sharing
- Document lessons learned
- Conduct tabletop exercises
- Share sanitized incident details
- Update response procedures

## Immediate Next Steps (Next Hour)

1. Isolate SRV-PROD-001 from the network
2. Notify key stakeholders of the incident
3. Begin forensic evidence collection
4. Check domain controllers and similar servers for signs of compromise
5. Identify and secure backup sources for eventual recovery

This is just one example of how Claude AI can help analyze and present security data. The AI can generate various types of reports, including:
- Incident response plans
- Threat intelligence reports
- Vulnerability assessments
- Security posture reviews
- Compliance reports

Note: In a real report, Claude AI would analyze actual CrowdStrike data and provide specific details about the incident. The examples above use dummy data to demonstrate the format and structure of the analysis.
```

## Features

- **OAuth2 Authentication**: Secure API access with token caching
- **Multi-Region Support**: Compatible with all CrowdStrike API regions
- **Comprehensive API Coverage**:
  - Detections
  - Host Details
  - IOCs (Indicators of Compromise)
  - Vulnerabilities (Spotlight)
  - Incidents
  - RTR (Real Time Response) Sessions
  - Falcon Discover Hosts
- **Flexible Filtering**: Support for various filter parameters
- **Formatted Output**: Human-readable output with emoji indicators
- **Error Handling**: Comprehensive error handling and logging
- **Async Operations**: All API calls are asynchronous for better performance

## Prerequisites

- Python 3.8 or higher
- CrowdStrike Falcon API credentials
- Required Python packages (see `requirements.txt`)
- Claude AI access (for MCP integration)

### MCP Installation

The Model Context Protocol (MCP) package is required for Claude AI integration. To install and set up MCP:

1. Visit [MCP for Developers](https://modelcontextprotocol.io/quickstart/server) for detailed installation instructions
2. Follow the server setup guide to:
   - Install the MCP SDK
   - Configure your environment
   - Set up the server connection
3. Verify the installation with `python -c "import mcp"`

Note: The security checks in this repository will skip MCP-related files as they are managed separately.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd crowdstrike-api
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env with your actual credentials
   # Never commit the .env file to version control
   ```

   Required environment variables:
   - `CROWDSTRIKE_CLIENT_ID`: Your CrowdStrike API client ID
   - `CROWDSTRIKE_CLIENT_SECRET`: Your CrowdStrike API client secret
   - `CROWDSTRIKE_API_REGION`: API region (default: US-1)

## Usage

### Basic Usage

```python
import asyncio
from crowdstrike_api import get_detections, get_host_details

async def main():
    # Get recent detections
    detections = await get_detections(days=7, severity='high', limit=5)
    print(detections)
    
    # Get host details
    host_info = await get_host_details(hostname='example-host')
    print(host_info)

if __name__ == "__main__":
    asyncio.run(main())
```

### Available Functions

1. **get_detections**
   ```python
   await get_detections(
       days=7,              # Look back period
       severity='high',     # Filter by severity
       status='new',        # Filter by status
       limit=5,            # Maximum results
       hostname='host',    # Filter by hostname
       technique='T1234'   # Filter by MITRE technique
   )
   ```

2. **get_host_details**
   ```python
   await get_host_details(
       host_id='id',       # Host ID (optional)
       hostname='host'     # Hostname (optional)
   )
   ```

3. **get_iocs**
   ```python
   await get_iocs(
       days=7,             # Look back period
       type='sha256',      # IOC type
       severity='high',    # Filter by severity
       limit=5            # Maximum results
   )
   ```

4. **get_spotlight_vulnerabilities**
   ```python
   await get_spotlight_vulnerabilities(
       days=7,             # Look back period
       severity='high',    # Filter by severity
       status='open',      # Filter by status
       limit=5,           # Maximum results
       hostname='host'    # Filter by hostname
   )
   ```

5. **get_incidents**
   ```python
   await get_incidents(
       days=7,             # Look back period
       status='new',       # Filter by status
       severity='high',    # Filter by severity
       limit=5            # Maximum results
   )
   ```

6. **get_rtr_sessions**
   ```python
   await get_rtr_sessions(
       days=7,             # Look back period
       status='active',    # Filter by status
       limit=5            # Maximum results
   )
   ```

7. **get_discover_hosts**
   ```python
   await get_discover_hosts(
       days=7,             # Look back period
       status='active',    # Filter by status
       limit=5            # Maximum results
   )
   ```

## Testing

Run the test suite:
```bash
python test_crowdstrike_api.py
```

The test suite verifies:
- API connectivity and authentication
- Parameter handling
- Response parsing
- Error handling
- Filter functionality

## API Regions

Reference Swagger - https://assets.falcon.crowdstrike.com/support/api/swagger.html

Supported regions:
- US-1: api.crowdstrike.com
- US-2: api.us-2.crowdstrike.com
- US-GOV-1: api.laggar.gcw.crowdstrike.com
- EU-1: api.eu-1.crowdstrike.com

## Error Handling

The integration includes comprehensive error handling:
- Authentication errors
- API rate limiting
- Invalid parameters
- Network issues
- Response parsing errors

All errors are logged with detailed information for debugging.

## Limitations

- Read-only operations only
- API rate limits apply
- Some endpoints may require specific API permissions
- Filter syntax follows CrowdStrike's FQL (Falcon Query Language)
- Currently only tested on Mac OSX
- Windows and Linux support coming in future releases
- VirusTotal integration to validate IOCs coming soon

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and feature requests, please create an issue in the repository.
