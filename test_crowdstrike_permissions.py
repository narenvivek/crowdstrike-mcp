import asyncio
import json
from datetime import datetime, timedelta
from crowdstrike_api import (
    make_api_request,
    CROWDSTRIKE_API_REGION,
    CROWDSTRIKE_API_REGIONS
)

class CrowdStrikePermissionChecker:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "api_region": CROWDSTRIKE_API_REGION,
            "base_url": CROWDSTRIKE_API_REGIONS.get(CROWDSTRIKE_API_REGION),
            "permissions": {}
        }

    async def check_endpoint(self, name: str, endpoint: str, method: str = "GET", params: dict = None, json_data: dict = None):
        """Check access to a specific API endpoint"""
        try:
            result = await make_api_request(endpoint, method, params, json_data)
            self.results["permissions"][name] = {
                "status": "✅",
                "message": "Access granted",
                "details": result.get("meta", {}),
                "resources": result.get("resources", [])
            }
        except Exception as e:
            error_details = {}
            if hasattr(e, 'response'):
                try:
                    error_details = e.response.json()
                except:
                    error_details = {"error": str(e)}
            
            self.results["permissions"][name] = {
                "status": "❌",
                "message": str(e),
                "details": error_details.get("meta", {}),
                "error_code": error_details.get("errors", [{}])[0].get("code", "unknown"),
                "error_message": error_details.get("errors", [{}])[0].get("message", str(e))
            }

    # Detection APIs
    async def check_detections(self):
        """Check Detections API permissions"""
        await self.check_endpoint(
            "detections",
            "/detects/queries/detects/v1",
            params={"limit": 1}
        )

    # Host APIs
    async def check_hosts(self):
        """Check Hosts API permissions"""
        await self.check_endpoint(
            "hosts",
            "/devices/queries/devices/v1",
            params={"limit": 1}
        )

    # IOC APIs
    async def check_ioc(self):
        """Check IOC API permissions"""
        await self.check_endpoint(
            "ioc",
            "/iocs/queries/indicators/v1",
            params={"limit": 1}
        )

    async def check_custom_indicators(self):
        """Check Custom Indicators API permissions"""
        try:
            result = await make_api_request(
                "/iocs/queries/indicators/v1",
                params={"limit": 1}
            )
            if result.get("resources"):
                indicator_id = result["resources"][0]
                await self.check_endpoint(
                    "custom_indicators",
                    "/iocs/entities/indicators/v1",
                    params={"ids": indicator_id}
                )
            else:
                self.results["permissions"]["custom_indicators"] = {
                    "status": "⚠️",
                    "message": "No indicators found to test with",
                    "details": {}
                }
        except Exception as e:
            self.results["permissions"]["custom_indicators"] = {
                "status": "❌",
                "message": str(e),
                "details": {}
            }

    # Threat Intelligence APIs
    async def check_threat_intel(self):
        """Check Threat Intelligence API permissions"""
        await self.check_endpoint(
            "threat_intel",
            "/intel/queries/indicators/v1",
            params={"limit": 1}
        )

    # Spotlight (Vulnerability Management) APIs
    async def check_spotlight(self):
        """Check Spotlight API permissions"""
        filter_str = f"created_timestamp:>='{(datetime.now() - timedelta(days=7)).isoformat()}'"
        await self.check_endpoint(
            "spotlight",
            "/spotlight/queries/vulnerabilities/v1",
            params={"filter": filter_str, "limit": 1}
        )

    # Firewall Management APIs
    async def check_firewall(self):
        """Check Firewall Management API permissions"""
        # Try both v1 and v2 endpoints
        await self.check_endpoint(
            "firewall_v1",
            "/fwmgr/queries/policies/v1",
            params={"limit": 1}
        )
        await self.check_endpoint(
            "firewall_v2",
            "/fwmgr/queries/policies/v2",
            params={"limit": 1}
        )

    # Incidents APIs
    async def check_incidents(self):
        """Check Incidents API permissions"""
        await self.check_endpoint(
            "incidents",
            "/incidents/queries/incidents/v1",
            params={"limit": 1}
        )

    # Real Time Response APIs
    async def check_rtr(self):
        """Check Real Time Response API permissions"""
        await self.check_endpoint(
            "rtr",
            "/real-time-response/queries/sessions/v1",
            params={"limit": 1}
        )

    # Falcon Discover APIs
    async def check_discover(self):
        """Check Falcon Discover API permissions"""
        await self.check_endpoint(
            "discover",
            "/discover/queries/hosts/v1",
            params={"limit": 1}
        )

    # Falcon Overwatch APIs
    async def check_overwatch(self):
        """Check Falcon Overwatch API permissions"""
        # Try both dashboard and incidents endpoints
        await self.check_endpoint(
            "overwatch_dashboard",
            "/overwatch-dashboards/queries/incidents/v1",
            params={"limit": 1}
        )
        await self.check_endpoint(
            "overwatch_incidents",
            "/overwatch/queries/incidents/v1",
            params={"limit": 1}
        )

    # Falcon Spotlight APIs
    async def check_spotlight_vulnerabilities(self):
        """Check Falcon Spotlight Vulnerabilities API permissions"""
        filter_str = f"created_timestamp:>='{(datetime.now() - timedelta(days=7)).isoformat()}'"
        await self.check_endpoint(
            "spotlight_vulnerabilities",
            "/spotlight/queries/vulnerabilities/v1",
            params={"filter": filter_str, "limit": 1}
        )

    # Falcon Device Control APIs
    async def check_device_control(self):
        """Check Falcon Device Control API permissions"""
        # Try both v1 and v2 endpoints
        await self.check_endpoint(
            "device_control_v1",
            "/device-control/queries/policies/v1",
            params={"limit": 1}
        )
        await self.check_endpoint(
            "device_control_v2",
            "/device-control/queries/policies/v2",
            params={"limit": 1}
        )

    def print_results(self):
        """Print the permission check results in a formatted way"""
        print("\n=== CrowdStrike API Permission Check ===")
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"API Region: {self.results['api_region']}")
        print(f"Base URL: {self.results['base_url']}")
        print("\nAvailable Regions:")
        for region, url in CROWDSTRIKE_API_REGIONS.items():
            print(f"  - {region}: {url}")
        
        print("\nAPI Permissions:")
        for name, result in self.results["permissions"].items():
            print(f"\n{name.upper()}:")
            print(f"  Status: {result['status']}")
            print(f"  Message: {result['message']}")
            if result.get('error_code'):
                print(f"  Error Code: {result['error_code']}")
                print(f"  Error Message: {result['error_message']}")
            if result.get('details'):
                print("  Details:")
                for key, value in result['details'].items():
                    print(f"    - {key}: {value}")

    def save_results(self, filename: str = "crowdstrike_permissions.json"):
        """Save the permission check results to a JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults saved to {filename}")

async def main():
    checker = CrowdStrikePermissionChecker()
    
    # Check all API permissions
    await checker.check_detections()
    await checker.check_hosts()
    await checker.check_ioc()
    await checker.check_custom_indicators()
    await checker.check_threat_intel()
    await checker.check_spotlight()
    await checker.check_firewall()
    await checker.check_incidents()
    await checker.check_rtr()
    await checker.check_discover()
    await checker.check_overwatch()
    await checker.check_spotlight_vulnerabilities()
    await checker.check_device_control()
    
    # Print and save results
    checker.print_results()
    checker.save_results()

if __name__ == "__main__":
    asyncio.run(main()) 