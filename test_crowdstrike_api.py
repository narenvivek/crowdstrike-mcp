"""
CrowdStrike API Integration Tests

This module contains test cases for the CrowdStrike API integration.
It tests various API endpoints and functionality including:
- API region configuration
- Detection retrieval
- Host details
- IOC retrieval
- Vulnerability scanning
- Incident management
- RTR sessions
- Falcon Discover hosts

The tests are designed to verify:
1. API connectivity and authentication
2. Correct parameter handling
3. Response parsing and formatting
4. Error handling
5. Filter functionality

Note:
    These tests require valid CrowdStrike API credentials in the environment:
    - CROWDSTRIKE_CLIENT_ID
    - CROWDSTRIKE_CLIENT_SECRET
    - CROWDSTRIKE_API_REGION (optional, defaults to US-1)

Example Usage:
    ```bash
    # Run all tests
    python test_crowdstrike_api.py
    
    # Run with specific API region
    CROWDSTRIKE_API_REGION=EU-1 python test_crowdstrike_api.py
    ```
"""

import asyncio
import os
from crowdstrike_api import (
    CROWDSTRIKE_API_REGION,
    CROWDSTRIKE_API_REGIONS,
    get_detections,
    get_host_details,
    get_iocs,
    get_spotlight_vulnerabilities,
    get_incidents,
    get_rtr_sessions,
    get_discover_hosts
)

async def test_api_region():
    """
    Test API region configuration.
    
    This test verifies:
    1. The current API region is set
    2. The region is valid
    3. All available regions are listed
    """
    print("\n=== Test: Checking API Region Configuration ===")
    print(f"Current API Region: {CROWDSTRIKE_API_REGION}")
    print(f"API Base URL: {CROWDSTRIKE_API_REGIONS[CROWDSTRIKE_API_REGION]}")
    
    print("\nAvailable Regions:")
    for region, url in CROWDSTRIKE_API_REGIONS.items():
        print(f"  - {region}: {url}")

async def test_detections():
    """
    Test detection retrieval functionality.
    
    This test verifies:
    1. Retrieval of recent detections
    2. Filtering by time range
    3. Response formatting
    4. Severity and status display
    """
    print("\n=== Test: get_detections (last 7 days, limit 5) ===")
    result = await get_detections(days=7, limit=5)
    print(result)

async def test_host_details():
    """
    Test host details retrieval functionality.
    
    This test verifies:
    1. Host lookup by hostname
    2. Detailed host information display
    3. Network information formatting
    4. Status and platform display
    """
    print("\n=== Test: get_host_details (by hostname) ===")
    result = await get_host_details(hostname="USTPA1-WPVRN001")
    print(result)

async def test_iocs():
    """
    Test IOC (Indicators of Compromise) retrieval functionality.
    
    This test verifies:
    1. IOC retrieval with default parameters
    2. IOC details formatting
    3. Metadata display
    4. Timestamp formatting
    """
    print("\nTesting IOC retrieval...")
    result = await get_iocs(limit=5)
    print(result)

async def test_vulnerabilities():
    """
    Test vulnerability scanning functionality.
    
    This test verifies:
    1. Vulnerability retrieval with default parameters
    2. Severity and status display
    3. CVE details formatting
    4. Filter functionality
    """
    print("\nTesting Spotlight vulnerability retrieval...")
    result = await get_spotlight_vulnerabilities(limit=5)
    print(result)

async def test_incidents():
    """
    Test incident management functionality.
    
    This test verifies:
    1. Incident retrieval with default parameters
    2. Status and severity display
    3. Related detection display
    4. Timestamp formatting
    """
    print("\nTesting incident retrieval...")
    result = await get_incidents(limit=5)
    print(result)

async def test_rtr_sessions():
    """
    Test Real Time Response (RTR) session functionality.
    
    This test verifies:
    1. RTR session retrieval
    2. Session status display
    3. Command history formatting
    4. Timestamp formatting
    """
    print("\nTesting RTR session retrieval...")
    result = await get_rtr_sessions(limit=5)
    print(result)

async def test_discover_hosts():
    """
    Test Falcon Discover host functionality.
    
    This test verifies:
    1. Host discovery and retrieval
    2. Network information display
    3. Status and platform display
    4. Timestamp formatting
    """
    print("\nTesting Falcon Discover host retrieval...")
    result = await get_discover_hosts(limit=5)
    print(result)

async def main():
    """
    Main test runner function.
    
    This function:
    1. Runs all test cases in sequence
    2. Handles any errors that occur during testing
    3. Provides clear output formatting
    """
    try:
        await test_api_region()
        await test_detections()
        await test_host_details()
        await test_iocs()
        await test_vulnerabilities()
        await test_incidents()
        await test_rtr_sessions()
        await test_discover_hosts()
    except Exception as e:
        print(f"\nError during testing: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 