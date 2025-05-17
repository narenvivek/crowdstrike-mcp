"""
CrowdStrike API Integration Module

This module provides a comprehensive interface to interact with the CrowdStrike Falcon API.
It implements various tools for retrieving security-related information such as detections,
host details, IOCs, vulnerabilities, incidents, RTR sessions, and discover hosts.

The module uses FastMCP for tool registration and provides async functions for all API operations.
All operations are read-only, as the API credentials have limited permissions.

Key Features:
- OAuth2 authentication with token caching
- Support for multiple API regions
- Comprehensive error handling and logging
- Formatted output with emoji indicators
- Flexible filtering options for all queries

Environment Variables Required:
- CROWDSTRIKE_CLIENT_ID: API client ID
- CROWDSTRIKE_CLIENT_SECRET: API client secret
- CROWDSTRIKE_API_REGION: API region (default: US-1)

Example Usage:
    ```python
    # Get recent detections
    detections = await get_detections(days=7, severity='high', limit=5)
    
    # Get host details
    host_info = await get_host_details(hostname='example-host')
    
    # Get vulnerabilities
    vulns = await get_spotlight_vulnerabilities(status='open', severity='critical')
    ```

Note:
    All API operations are read-only. Creating, updating, or deleting resources is not supported
    with the current API credentials.
"""

import os
import httpx
import json
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import logging
import sys
import time
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("crowdstrike")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Constants
CROWDSTRIKE_API_REGIONS = {
    "US-1": "api.crowdstrike.com",
    "US-2": "api.us-2.crowdstrike.com",
    "US-GOV-1": "api.laggar.gcw.crowdstrike.com",
    "EU-1": "api.eu-1.crowdstrike.com"
}

# Get the API region from environment variable, default to US-1
CROWDSTRIKE_API_REGION = os.getenv("CROWDSTRIKE_API_REGION", "US-1")
CROWDSTRIKE_API_BASE = f"https://{CROWDSTRIKE_API_REGIONS.get(CROWDSTRIKE_API_REGION, CROWDSTRIKE_API_REGIONS['US-1'])}"

CROWDSTRIKE_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID")
CROWDSTRIKE_CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET")

# Token cache
_token_cache = {
    "token": None,
    "expires_at": 0
}

def format_timestamp(timestamp: Optional[str]) -> str:
    """
    Format a timestamp string to a more readable format.
    
    Args:
        timestamp: ISO format timestamp string (e.g., '2025-05-17T15:21:37Z')
        
    Returns:
        Formatted timestamp string (e.g., '2025-05-17 15:21:37 UTC')
        Returns 'Unknown' if timestamp is None or invalid
    """
    if not timestamp:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return timestamp

def format_severity(severity: Optional[str]) -> str:
    """
    Format a severity level with emoji indicators.
    
    Args:
        severity: Severity level as string (e.g., '80', '70', '40', '20')
        
    Returns:
        Formatted severity string with emoji (e.g., '🔴 Critical (80)')
        Returns 'Unknown' if severity is None or invalid
    """
    if not severity:
        return "Unknown"
    try:
        severity = int(severity)
        if severity >= 80:
            return f"🔴 Critical ({severity})"
        elif severity >= 70:
            return f"🟠 High ({severity})"
        elif severity >= 40:
            return f"🟡 Medium ({severity})"
        elif severity >= 20:
            return f"🟢 Low ({severity})"
        else:
            return f"⚪ Informational ({severity})"
    except:
        return f"Unknown ({severity})"

async def get_oauth_token() -> str:
    """
    Get OAuth2 token for CrowdStrike API with caching.
    
    This function implements token caching to avoid unnecessary API calls.
    The token is cached for its lifetime minus 5 minutes to ensure it's always valid.
    
    Returns:
        Valid OAuth2 access token
        
    Raises:
        ValueError: If credentials are missing or token request fails
    """
    global _token_cache
    
    # Check if we have a valid cached token
    current_time = time.time()
    if _token_cache["token"] and current_time < _token_cache["expires_at"]:
        return _token_cache["token"]

    if not CROWDSTRIKE_CLIENT_ID or not CROWDSTRIKE_CLIENT_SECRET:
        raise ValueError("CrowdStrike credentials not found in environment variables")

    token_url = f"{CROWDSTRIKE_API_BASE}/oauth2/token"
    token_data = {
        "client_id": CROWDSTRIKE_CLIENT_ID,
        "client_secret": CROWDSTRIKE_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0
            )
            
            if response.status_code not in (200, 201):
                raise ValueError(f"Failed to get OAuth token: {response.text}")
                
            token_data = response.json()
            token = token_data.get("access_token")
            
            if not token:
                raise ValueError("No access token in response")
            
            # Cache the token with expiration
            _token_cache["token"] = token
            _token_cache["expires_at"] = current_time + token_data.get("expires_in", 1800) - 300  # 5 minutes buffer
            
            return token
        except Exception as e:
            logger.error(f"Error getting OAuth token: {str(e)}")
            raise ValueError(f"Failed to get OAuth token: {str(e)}")

async def make_api_request(endpoint: str, method: str = "GET", params: Dict = None, json_data: Dict = None) -> Dict:
    """
    Make an authenticated request to the CrowdStrike API.
    
    This function handles authentication, request formatting, and error handling
    for all API calls. It automatically adds the OAuth token and handles common
    error cases.
    
    Args:
        endpoint: API endpoint path (e.g., '/detects/queries/detects/v1')
        method: HTTP method ('GET' or 'POST')
        params: Query parameters for GET requests
        json_data: JSON data for POST requests
        
    Returns:
        API response as dictionary
        
    Raises:
        ValueError: If the API request fails or returns an error
    """
    url = f"{CROWDSTRIKE_API_BASE}{endpoint}"
    headers = {
        "Authorization": f"Bearer {await get_oauth_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Log request details for debugging
    logger.info(f"Making {method} request to {url}")
    if params:
        logger.info(f"With params: {params}")
    
    async with httpx.AsyncClient() as client:
        try:
            if method == "GET":
                response = await client.get(url, headers=headers, params=params, timeout=30.0)
            else:
                response = await client.post(url, headers=headers, json=json_data, timeout=30.0)
                
            if response.status_code == 403:
                error_msg = f"API request failed with status 403: {response.text}\nPlease ensure:\n1. Your API client has the correct scopes enabled\n2. You're using the correct API region (current: {CROWDSTRIKE_API_REGION})\n3. Your credentials are valid"
                logger.error(error_msg)
                raise ValueError(error_msg)
            elif response.status_code != 200:
                error_msg = f"API request failed with status {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            return response.json()
        except httpx.ConnectError as e:
            error_msg = f"Connection error: {str(e)}\nPlease verify you're using the correct API region (current: {CROWDSTRIKE_API_REGION})"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

async def check_api_permissions() -> Dict[str, bool]:
    """Check which API permissions are available for the current credentials."""
    try:
        # Try to access different API endpoints to check permissions
        permissions = {
            "detections": False,
            "hosts": False
        }
        
        # Check detections permission
        try:
            await make_api_request("/detects/queries/detects/v1", method="GET", params={"limit": 1})
            permissions["detections"] = True
        except Exception as e:
            if "403" in str(e):
                logger.warning("No permission to access detections API")
            else:
                logger.error(f"Error checking detections permission: {str(e)}")

        # Check hosts permission
        try:
            await make_api_request("/devices/queries/devices/v1", method="GET", params={"limit": 1})
            permissions["hosts"] = True
        except Exception as e:
            if "403" in str(e):
                logger.warning("No permission to access hosts API")
            else:
                logger.error(f"Error checking hosts permission: {str(e)}")

        return permissions
    except Exception as e:
        logger.error(f"Error checking API permissions: {str(e)}")
        return {
            "detections": False,
            "hosts": False
        }

@mcp.tool()
async def get_detections(
    days: int = 7,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = 5,
    hostname: Optional[str] = None,
    technique: Optional[str] = None
) -> str:
    """
    Retrieve recent CrowdStrike detections with flexible filtering.

    Args:
        days: Number of days to look back (default: 7)
        severity: Filter by severity (optional, e.g., '80', '70', etc.)
        status: Filter by status (optional, e.g., 'new', 'in_progress', 'closed')
        limit: Maximum number of detections to return (default: 5)
        hostname: Filter by device hostname (optional)
        technique: Filter by MITRE technique (optional)
    Returns:
        A formatted string with detection summaries or an error message.
    """
    try:
        # Validate limit
        if limit is not None:
            try:
                limit = int(limit)
                if limit < 1:
                    return "Error: limit must be a positive integer."
            except Exception:
                return "Error: limit must be an integer."
        else:
            limit = 5

        # Calculate start time
        start_time = (datetime.now(UTC) - timedelta(days=days)).isoformat()

        # Build filter string
        filter_parts = [f"created_timestamp:>='{start_time}'"]
        if severity:
            filter_parts.append(f"behaviors.severity:'{severity}'")
        if status:
            filter_parts.append(f"status:'{status}'")
        if hostname:
            filter_parts.append(f"device.hostname:'{hostname}'")
        if technique:
            filter_parts.append(f"behaviors.technique:'{technique}'")
        filter_str = "+".join(filter_parts)

        logger.info(f"Using filter: {filter_str}")

        # Query for detection IDs
        query_response = await make_api_request(
            "/detects/queries/detects/v1",
            method="GET",
            params={"filter": filter_str, "limit": limit}
        )
        detection_ids = query_response.get("resources", [])
        if not detection_ids:
            return "No detections found for the specified criteria."

        # Get detection details
        detail_response = await make_api_request(
            "/detects/entities/summaries/GET/v1",
            method="POST",
            json_data={"ids": detection_ids}
        )
        detections = detail_response.get("resources", [])
        if not detections:
            return "No detection details found for the specified IDs."

        # Format results
        results = [f"🔍 Found {len(detections)} detections"]
        for detection in detections:
            # Find highest severity and collect techniques/tactics from behaviors
            behaviors = detection.get('behaviors', [])
            highest_severity = None
            techniques = set()
            tactics = set()
            behavior_descriptions = set()
            
            for behavior in behaviors:
                if behavior.get('severity'):
                    try:
                        severity = int(behavior.get('severity'))
                        if highest_severity is None or severity > highest_severity:
                            highest_severity = severity
                    except (ValueError, TypeError):
                        continue
                if behavior.get('technique'):
                    techniques.add(behavior.get('technique'))
                if behavior.get('tactic'):
                    tactics.add(behavior.get('tactic'))
                if behavior.get('description'):
                    behavior_descriptions.add(behavior.get('description'))

            detection_info = []
            detection_info.append(f"\n📋 Detection ID: {detection.get('detection_id', 'Unknown')}")
            detection_info.append(f"⚠️ Severity: {format_severity(str(highest_severity) if highest_severity is not None else None)}")
            detection_info.append(f"📊 Status: {detection.get('status', 'Unknown')}")
            detection_info.append(f"🕒 Created: {format_timestamp(detection.get('created_timestamp'))}")
            detection_info.append(f"🔄 Updated: {format_timestamp(detection.get('updated_timestamp'))}")

            # Device information
            device = detection.get('device', {})
            detection_info.append(f"\n💻 Device Information:")
            detection_info.append(f"  Host: {device.get('hostname', 'Unknown')}")
            detection_info.append(f"  Platform: {device.get('platform_name', 'Unknown')}")
            detection_info.append(f"  OS Version: {device.get('os_version', 'Unknown')}")

            # Detection details
            detection_info.append(f"\n📝 Detection Details:")
            detection_info.append(f"  Description: {detection.get('description', 'No description available')}")
            detection_info.append(f"  Technique: {', '.join(techniques) if techniques else 'Unknown'}")
            detection_info.append(f"  Tactic: {', '.join(tactics) if tactics else 'Unknown'}")
            detection_info.append(f"  Unique Behaviors: {len(behavior_descriptions)}")

            # Behaviors
            if behaviors:
                detection_info.append("\n🔍 Behaviors:")
                for behavior in behaviors:
                    detection_info.append(f"  - {behavior.get('description', 'No description')}")
                    if behavior.get('technique'):
                        detection_info.append(f"    🎯 Technique: {behavior.get('technique')}")
                    if behavior.get('tactic'):
                        detection_info.append(f"    🎭 Tactic: {behavior.get('tactic')}")
                    if behavior.get('severity'):
                        detection_info.append(f"    ⚠️ Severity: {format_severity(behavior.get('severity'))}")
                    if behavior.get('process_name'):
                        detection_info.append(f"    💻 Process: {behavior.get('process_name')}")
                    if behavior.get('file_name'):
                        detection_info.append(f"    📄 File: {behavior.get('file_name')}")
                    if behavior.get('command_line'):
                        detection_info.append(f"    ⌨️ Command: {behavior.get('command_line')}")
            results.append("\n".join(detection_info))
            results.append("-" * 80)
        return "\n".join(results)
    except Exception as e:
        logger.error(f"Error in get_detections: {str(e)}")
        return f"Error fetching detections: {str(e)}"

@mcp.tool()
async def get_host_details(host_id: Optional[str] = None, hostname: Optional[str] = None) -> str:
    """Get detailed information about a host using the OAuth2 API.
    
    Args:
        host_id: CrowdStrike device ID (optional)
        hostname: Hostname to lookup (optional)
        
    Note: At least one of host_id or hostname must be provided
    """
    if not host_id and not hostname:
        return "Error: Either host_id or hostname must be provided"
        
    try:
        # If only hostname is provided, get the host_id first
        if hostname and not host_id:
            query_response = await make_api_request(
                "/devices/queries/devices/v1",
                method="GET",
                params={"filter": f"hostname:'{hostname}'"}
            )
            
            if not query_response.get("resources"):
                return f"No hosts found with hostname: {hostname}"
                
            host_id = query_response["resources"][0]
        
        # Get host details
        detail_response = await make_api_request(
            "/devices/entities/devices/v1",
            method="GET",
            params={"ids": host_id}
        )
        
        if not detail_response.get("resources"):
            return f"No host details found for ID: {host_id}"
            
        host = detail_response["resources"][0]
        
        # Format host information
        result = [f"🖥️ Host Details: {host.get('hostname', 'Unknown')}"]
        result.append(f"📋 Device ID: {host.get('device_id', 'Unknown')}")
        result.append(f"💻 Platform: {host.get('platform_name', 'Unknown')}")
        result.append(f"🏢 MAC: {host.get('mac_address', 'Unknown')}")
        result.append(f"🔌 IP: {host.get('local_ip', 'Unknown')}")
        result.append(f"👤 First Seen: {format_timestamp(host.get('first_seen'))}")
        result.append(f"🕒 Last Seen: {format_timestamp(host.get('last_seen'))}")
        result.append(f"🔄 Status: {host.get('status', 'Unknown')}")
        
        # Add additional useful information
        if host.get('os_version'):
            result.append(f"💿 OS Version: {host.get('os_version')}")
        if host.get('kernel_version'):
            result.append(f"🔧 Kernel Version: {host.get('kernel_version')}")
        if host.get('external_ip'):
            result.append(f"🌐 External IP: {host.get('external_ip')}")
        if host.get('agent_version'):
            result.append(f"🛡️ Agent Version: {host.get('agent_version')}")
        
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in get_host_details: {str(e)}")
        return f"Error retrieving host details: {str(e)}"

@mcp.tool()
async def get_iocs(
    days: int = 7,
    type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: Optional[int] = 5
) -> str:
    """
    Retrieve CrowdStrike IOCs with flexible filtering (Read-Only).

    Args:
        days: Number of days to look back (default: 7)
        type: Filter by IOC type (optional, e.g., 'sha256', 'domain', 'ip')
        severity: Filter by severity (optional, e.g., 'high', 'medium', 'low')
        limit: Maximum number of IOCs to return (default: 5)
    Returns:
        A formatted string with IOC summaries or an error message.
    Note:
        This is a read-only operation. Creating, updating, or deleting IOCs is not supported.
    """
    try:
        # Build filter string
        filter_parts = []
        if type:
            filter_parts.append(f"type:'{type}'")
        if severity:
            filter_parts.append(f"severity:'{severity}'")
        filter_str = "+".join(filter_parts) if filter_parts else None

        # Query for IOC IDs
        query_response = await make_api_request(
            "/iocs/queries/indicators/v1",
            method="GET",
            params={"filter": filter_str, "limit": limit} if filter_str else {"limit": limit}
        )
        ioc_ids = query_response.get("resources", [])
        if not ioc_ids:
            return "No IOCs found for the specified criteria."

        # Get IOC details
        detail_response = await make_api_request(
            "/iocs/entities/indicators/v1",
            method="GET",
            params={"ids": ioc_ids}
        )
        iocs = detail_response.get("resources", [])
        if not iocs:
            return "No IOC details found for the specified IDs."

        # Format results
        results = [f"🔍 Found {len(iocs)} IOCs"]
        for ioc in iocs:
            ioc_info = []
            ioc_info.append(f"\n📋 IOC ID: {ioc.get('id', 'Unknown')}")
            ioc_info.append(f"📝 Type: {ioc.get('type', 'Unknown')}")
            ioc_info.append(f"💾 Value: {ioc.get('value', 'Unknown')}")
            ioc_info.append(f"⚠️ Severity: {ioc.get('severity', 'Unknown')}")
            ioc_info.append(f"🎯 Action: {ioc.get('action', 'Unknown')}")
            ioc_info.append(f"📄 Description: {ioc.get('description', 'No description available')}")
            ioc_info.append(f"💻 Platforms: {', '.join(ioc.get('platforms', ['Unknown']))}")
            ioc_info.append(f"🕒 Created: {format_timestamp(ioc.get('created_on'))}")
            ioc_info.append(f"👤 Created By: {ioc.get('created_by', 'Unknown')}")
            ioc_info.append(f"🔄 Modified: {format_timestamp(ioc.get('modified_on'))}")
            ioc_info.append(f"👤 Modified By: {ioc.get('modified_by', 'Unknown')}")
            
            # Metadata
            if ioc.get('metadata'):
                ioc_info.append("\n📊 Metadata:")
                for key, value in ioc.get('metadata', {}).items():
                    ioc_info.append(f"  - {key}: {value}")
            
            results.append("\n".join(ioc_info))
            results.append("-" * 80)
        return "\n".join(results)
    except Exception as e:
        logger.error(f"Error in get_iocs: {str(e)}")
        return f"Error fetching IOCs: {str(e)}"

@mcp.tool()
async def get_spotlight_vulnerabilities(
    days: int = 7,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = 5,
    hostname: Optional[str] = None
) -> str:
    """
    Retrieve CrowdStrike Spotlight vulnerabilities with flexible filtering (Read-Only).

    Args:
        days: Number of days to look back (default: 7)
        severity: Filter by severity (optional, e.g., 'high', 'medium', 'low')
        status: Filter by status (optional, e.g., 'open', 'closed')
        limit: Maximum number of vulnerabilities to return (default: 5)
        hostname: Filter by device hostname (optional)
    Returns:
        A formatted string with vulnerability summaries or an error message.
    Note:
        This is a read-only operation. Updating vulnerability status or remediation is not supported.
    """
    try:
        # Build filter string according to FQL syntax
        filter_parts = []
        if status:
            filter_parts.append(f"status:'{status}'")
        else:
            filter_parts.append("status:'open'")  # Default to open vulnerabilities
        if severity:
            filter_parts.append(f"severity:'{severity}'")
        if hostname:
            filter_parts.append(f"hostname:'{hostname}'")
        filter_str = "+".join(filter_parts)  # Use + for combining filters

        # Query for vulnerability IDs
        query_response = await make_api_request(
            "/spotlight/queries/vulnerabilities/v1",
            method="GET",
            params={
                "filter": filter_str,
                "limit": limit
            }
        )
        vuln_ids = query_response.get("resources", [])
        if not vuln_ids:
            return "No vulnerabilities found for the specified criteria."

        # Get vulnerability details
        detail_response = await make_api_request(
            "/spotlight/entities/vulnerabilities/v2",
            method="GET",
            params={"ids": vuln_ids}
        )
        vulnerabilities = detail_response.get("resources", [])
        if not vulnerabilities:
            return "No vulnerability details found for the specified IDs."

        # Format results
        results = [f"🔍 Found {len(vulnerabilities)} vulnerabilities"]
        for vuln in vulnerabilities:
            vuln_info = []
            vuln_info.append(f"\n📋 Vulnerability ID: {vuln.get('id', 'Unknown')}")
            vuln_info.append(f"📝 CVE ID: {vuln.get('cve', {}).get('id', 'Unknown')}")
            
            # Map severity to readable format
            severity_map = {
                'Critical': '🔴 Critical',
                'High': '🟠 High',
                'Medium': '🟡 Medium',
                'Low': '🟢 Low',
                'Informational': '⚪ Informational'
            }
            severity = vuln.get('severity', 'Unknown')
            severity_display = severity_map.get(severity, f'Unknown ({severity})')
            vuln_info.append(f"⚠️ Severity: {severity_display}")
            
            vuln_info.append(f"📄 Description: {vuln.get('description', 'No description available')}")
            vuln_info.append(f"💻 Host: {vuln.get('host_info', {}).get('hostname', 'Unknown')}")
            
            # Map status to readable format
            status_map = {
                'open': '🔴 Open',
                'closed': '🟢 Closed',
                'in_progress': '🟡 In Progress'
            }
            status = vuln.get('status', 'Unknown')
            status_display = status_map.get(status, f'Unknown ({status})')
            vuln_info.append(f"🔄 Status: {status_display}")
            
            vuln_info.append(f"🕒 Created: {format_timestamp(vuln.get('created_timestamp'))}")
            vuln_info.append(f"🔄 Updated: {format_timestamp(vuln.get('updated_timestamp'))}")
            
            # Additional details
            if vuln.get('cve'):
                vuln_info.append("\n📊 CVE Details:")
                cve = vuln.get('cve', {})
                if cve.get('base_score'):
                    vuln_info.append(f"  - Base Score: {cve.get('base_score')}")
                if cve.get('exploitability_score'):
                    vuln_info.append(f"  - Exploitability Score: {cve.get('exploitability_score')}")
                if cve.get('impact_score'):
                    vuln_info.append(f"  - Impact Score: {cve.get('impact_score')}")
                if cve.get('vector'):
                    vuln_info.append(f"  - CVSS Vector: {cve.get('vector')}")
            
            results.append("\n".join(vuln_info))
            results.append("-" * 80)
        return "\n".join(results)
    except Exception as e:
        logger.error(f"Error in get_spotlight_vulnerabilities: {str(e)}")
        return f"Error fetching vulnerabilities: {str(e)}"

@mcp.tool()
async def get_incidents(
    days: int = 7,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: Optional[int] = 5
) -> str:
    """
    Retrieve CrowdStrike incidents with flexible filtering (Read-Only).

    Args:
        days: Number of days to look back (default: 7)
        status: Filter by status (optional, e.g., 'new', 'in_progress', 'closed')
        severity: Filter by severity (optional, e.g., 'high', 'medium', 'low')
        limit: Maximum number of incidents to return (default: 5)
    Returns:
        A formatted string with incident summaries or an error message.
    Note:
        This is a read-only operation. Creating, updating, or closing incidents is not supported.
    """
    try:
        # Build filter string according to FQL syntax
        filter_parts = []
        if status:
            filter_parts.append(f"status:'{status}'")
        if severity:
            filter_parts.append(f"severity:'{severity}'")
        filter_str = "+".join(filter_parts) if filter_parts else None

        # Query for incident IDs
        query_response = await make_api_request(
            "/incidents/queries/incidents/v1",
            method="GET",
            params={
                "filter": filter_str,
                "limit": limit
            } if filter_str else {
                "limit": limit
            }
        )
        incident_ids = query_response.get("resources", [])
        if not incident_ids:
            return "No incidents found for the specified criteria."

        # Get incident details - using POST as per API documentation
        detail_response = await make_api_request(
            "/incidents/entities/incidents/GET/v1",
            method="POST",
            json_data={"ids": incident_ids}
        )
        incidents = detail_response.get("resources", [])
        if not incidents:
            return "No incident details found for the specified IDs."

        # Format results
        results = [f"🔍 Found {len(incidents)} incidents"]
        for incident in incidents:
            incident_info = []
            incident_info.append(f"\n📋 Incident ID: {incident.get('incident_id', 'Unknown')}")
            
            # Map status codes to readable values
            status_code = incident.get('status')
            status_map = {
                '20': '🔴 New',
                '30': '🟡 In Progress',
                '40': '🟢 Closed',
                '50': '🟠 Reopened'
            }
            status = status_map.get(str(status_code), f'Unknown ({status_code})')
            incident_info.append(f"🔄 Status: {status}")
            
            # Map severity codes to readable values
            severity_code = incident.get('severity')
            severity_map = {
                '10': '⚪ Low',
                '20': '🟢 Medium',
                '30': '🟠 High',
                '40': '🔴 Critical'
            }
            severity = severity_map.get(str(severity_code), f'Unknown ({severity_code})')
            incident_info.append(f"⚠️ Severity: {severity}")
            
            incident_info.append(f"📄 Title: {incident.get('title', 'No title available')}")
            incident_info.append(f"🕒 Created: {format_timestamp(incident.get('created_timestamp'))}")
            incident_info.append(f"🔄 Updated: {format_timestamp(incident.get('updated_timestamp'))}")
            
            # Additional details
            if incident.get('description'):
                incident_info.append(f"\n📝 Description: {incident.get('description')}")
            if incident.get('tags'):
                incident_info.append(f"\n🏷️ Tags: {', '.join(incident.get('tags', []))}")
            
            # Add detection details if available
            if incident.get('detections'):
                incident_info.append("\n🔍 Related Detections:")
                for detection in incident.get('detections', []):
                    incident_info.append(f"  - Detection ID: {detection.get('detection_id', 'Unknown')}")
                    incident_info.append(f"    Status: {detection.get('status', 'Unknown')}")
                    incident_info.append(f"    Severity: {detection.get('severity', 'Unknown')}")
            
            results.append("\n".join(incident_info))
            results.append("-" * 80)
        return "\n".join(results)
    except Exception as e:
        logger.error(f"Error in get_incidents: {str(e)}")
        return f"Error fetching incidents: {str(e)}"

@mcp.tool()
async def get_rtr_sessions(
    days: int = 7,
    status: Optional[str] = None,
    limit: Optional[int] = 5
) -> str:
    """
    Retrieve CrowdStrike Real Time Response (RTR) sessions (Read-Only).

    Args:
        days: Number of days to look back (default: 7)
        status: Filter by status (optional, e.g., 'active', 'completed')
        limit: Maximum number of sessions to return (default: 5)
    Returns:
        A formatted string with RTR session summaries or an error message.
    Note:
        This is a read-only operation. Creating new RTR sessions or executing commands is not supported.
    """
    try:
        # Build filter string
        filter_parts = []
        if status:
            filter_parts.append(f"status:'{status}'")
        filter_str = "+".join(filter_parts) if filter_parts else None

        # Query for RTR sessions
        query_response = await make_api_request(
            "/real-time-response/queries/sessions/v1",
            method="GET",
            params={"filter": filter_str, "limit": limit} if filter_str else {"limit": limit}
        )
        sessions = query_response.get("resources", [])
        if not sessions:
            return "No RTR sessions found for the specified criteria."

        # Format results
        results = [f"🔍 Found {len(sessions)} RTR sessions"]
        for session in sessions:
            session_info = []
            session_info.append(f"\n📋 Session ID: {session.get('session_id', 'Unknown')}")
            session_info.append(f"💻 Host: {session.get('hostname', 'Unknown')}")
            session_info.append(f"🔄 Status: {session.get('status', 'Unknown')}")
            session_info.append(f"🕒 Created: {format_timestamp(session.get('created_timestamp'))}")
            session_info.append(f"🔄 Updated: {format_timestamp(session.get('updated_timestamp'))}")
            
            # Additional details
            if session.get('commands'):
                session_info.append("\n⌨️ Commands:")
                for cmd in session.get('commands', []):
                    session_info.append(f"  - {cmd.get('command', 'Unknown')}")
                    session_info.append(f"    Status: {cmd.get('status', 'Unknown')}")
                    session_info.append(f"    Output: {cmd.get('output', 'No output')}")
            
            results.append("\n".join(session_info))
            results.append("-" * 80)
        return "\n".join(results)
    except Exception as e:
        logger.error(f"Error in get_rtr_sessions: {str(e)}")
        return f"Error fetching RTR sessions: {str(e)}"

@mcp.tool()
async def get_discover_hosts(
    days: int = 7,
    status: Optional[str] = None,
    limit: Optional[int] = 5
) -> str:
    """
    Retrieve CrowdStrike Falcon Discover hosts (Read-Only).

    Args:
        days: Number of days to look back (default: 7)
        status: Filter by status (optional, e.g., 'active', 'inactive')
        limit: Maximum number of hosts to return (default: 5)
    Returns:
        A formatted string with host summaries or an error message.
    Note:
        This is a read-only operation. Adding or modifying hosts is not supported.
    """
    try:
        # Build filter string according to FQL syntax
        filter_parts = []
        if status:
            filter_parts.append(f"status:'{status}'")
        filter_str = "+".join(filter_parts) if filter_parts else None

        # Query for hosts
        query_response = await make_api_request(
            "/discover/queries/hosts/v1",
            method="GET",
            params={
                "filter": filter_str,
                "limit": limit,
                "sort": "last_seen_timestamp|desc"  # Sort by most recently seen
            } if filter_str else {
                "limit": limit,
                "sort": "last_seen_timestamp|desc"
            }
        )
        hosts = query_response.get("resources", [])
        if not hosts:
            return "No hosts found for the specified criteria."

        # Format results
        results = [f"🔍 Found {len(hosts)} hosts"]
        for host_id in hosts:
            # Get host details
            detail_response = await make_api_request(
                "/discover/entities/hosts/v1",
                method="GET",
                params={"ids": host_id}
            )
            host_details = detail_response.get("resources", [{}])[0]
            
            host_info = []
            host_info.append(f"\n📋 Host ID: {host_id}")
            host_info.append(f"💻 Hostname: {host_details.get('hostname', 'Unknown')}")
            
            # Map status to readable format
            status_map = {
                'active': '🟢 Active',
                'inactive': '🔴 Inactive',
                'maintenance': '🟡 Maintenance',
                'normal': '🟢 Normal',
                'offline': '🔴 Offline',
                'online': '🟢 Online'
            }
            status = host_details.get('status', 'Unknown')
            status_display = status_map.get(status, f'Unknown ({status})')
            host_info.append(f"🔄 Status: {status_display}")
            
            # Add OS information
            if host_details.get('os_version'):
                host_info.append(f"💿 OS: {host_details.get('os_version')}")
            elif host_details.get('platform_name'):
                host_info.append(f"💿 Platform: {host_details.get('platform_name')}")
            
            # Add timestamps
            if host_details.get('first_seen_timestamp'):
                host_info.append(f"👤 First Seen: {format_timestamp(host_details.get('first_seen_timestamp'))}")
            if host_details.get('last_seen_timestamp'):
                host_info.append(f"🕒 Last Seen: {format_timestamp(host_details.get('last_seen_timestamp'))}")
            
            # Add network information if available
            if host_details.get('local_ip_addresses'):
                host_info.append(f"\n🌐 Network Information:")
                for ip in host_details.get('local_ip_addresses', []):
                    host_info.append(f"  - IP Address: {ip}")
            if host_details.get('mac_addresses'):
                for mac in host_details.get('mac_addresses', []):
                    host_info.append(f"  - MAC Address: {mac}")
            
            # Add additional details
            if host_details.get('tags'):
                host_info.append(f"\n🏷️ Tags: {', '.join(host_details.get('tags', []))}")
            
            results.append("\n".join(host_info))
            results.append("-" * 80)
        return "\n".join(results)
    except Exception as e:
        logger.error(f"Error in get_discover_hosts: {str(e)}")
        return f"Error fetching hosts: {str(e)}"

if __name__ == "__main__":
    # Run the MCP server
    mcp.run(transport='stdio') 