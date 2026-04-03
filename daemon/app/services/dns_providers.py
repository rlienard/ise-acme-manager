"""
DNS Provider clients for ACME DNS-01 challenge automation.
"""

import logging
import requests

logger = logging.getLogger(__name__)


class CloudflareDNS:
    def __init__(self, config: dict):
        self.api_token = config.get("cloudflare_api_token", "")
        self.zone_id = config.get("cloudflare_zone_id", "")
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def create_txt_record(self, name: str, value: str, ttl: int = 120) -> str:
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records"
        payload = {"type": "TXT", "name": name, "content": value, "ttl": ttl}
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        result = response.json()
        if result.get("success"):
            record_id = result["result"]["id"]
            logger.info(f"DNS TXT created: {name} (ID: {record_id})")
            return record_id
        raise Exception(f"Cloudflare error: {result.get('errors')}")

    def delete_txt_record(self, record_id: str):
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        logger.info(f"DNS TXT deleted: {record_id}")

    def test_connection(self) -> dict:
        try:
            url = f"{self.base_url}/zones/{self.zone_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            zone = response.json().get("result", {})
            return {"success": True, "message": f"Connected to zone: {zone.get('name', 'unknown')}"}
        except Exception as e:
            return {"success": False, "message": str(e)}


class AWSRoute53DNS:
    def __init__(self, config: dict):
        import boto3
        self.client = boto3.client("route53", region_name=config.get("aws_region", "us-east-1"))
        self.hosted_zone_id = config.get("aws_hosted_zone_id", "")

    def create_txt_record(self, name: str, value: str, ttl: int = 120) -> str:
        response = self.client.change_resource_record_sets(
            HostedZoneId=self.hosted_zone_id,
            ChangeBatch={"Changes": [{"Action": "UPSERT", "ResourceRecordSet": {
                "Name": name, "Type": "TXT", "TTL": ttl,
                "ResourceRecords": [{"Value": f'"{value}"'}]
            }}]}
        )
        return response["ChangeInfo"]["Id"]

    def delete_txt_record(self, record_id: str, name: str = None, value: str = None):
        if name and value:
            self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": {
                    "Name": name, "Type": "TXT", "TTL": 120,
                    "ResourceRecords": [{"Value": f'"{value}"'}]
                }}]}
            )

    def test_connection(self) -> dict:
        try:
            self.client.get_hosted_zone(Id=self.hosted_zone_id)
            return {"success": True, "message": "Connected to Route53"}
        except Exception as e:
            return {"success": False, "message": str(e)}


class AzureDNS:
    def __init__(self, config: dict):
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.dns import DnsManagementClient
        credential = DefaultAzureCredential()
        self.client = DnsManagementClient(credential, config.get("azure_subscription_id", ""))
        self.resource_group = config.get("azure_resource_group", "")
        self.zone_name = config.get("azure_dns_zone_name", "")

    def create_txt_record(self, name: str, value: str, ttl: int = 120) -> str:
        relative = name.replace(f".{self.zone_name}", "")
        from azure.mgmt.dns.models import RecordSet, TxtRecord
        self.client.record_sets.create_or_update(
            self.resource_group, self.zone_name, relative, "TXT",
            RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[value])])
        )
        return relative

    def delete_txt_record(self, record_id: str, **kwargs):
        self.client.record_sets.delete(
            self.resource_group, self.zone_name, record_id, "TXT"
        )

    def test_connection(self) -> dict:
        try:
            self.client.zones.get(self.resource_group, self.zone_name)
            return {"success": True, "message": "Connected to Azure DNS"}
        except Exception as e:
            return {"success": False, "message": str(e)}


class OVHCloudDNS:
    def __init__(self, config: dict):
        import ovh
        self.client = ovh.Client(
            endpoint=config.get("ovh_endpoint", "ovh-eu"),
            application_key=config.get("ovh_application_key", ""),
            application_secret=config.get("ovh_application_secret", ""),
            consumer_key=config.get("ovh_consumer_key", ""),
        )
        self.zone_name = config.get("ovh_dns_zone", "")

    def create_txt_record(self, name: str, value: str, ttl: int = 120) -> str:
        relative = name.replace(f".{self.zone_name}", "").rstrip(".")
        result = self.client.post(
            f"/domain/zone/{self.zone_name}/record",
            fieldType="TXT",
            subDomain=relative,
            target=value,
            ttl=ttl,
        )
        record_id = str(result["id"])
        self.client.post(f"/domain/zone/{self.zone_name}/refresh")
        logger.info(f"DNS TXT created: {name} (ID: {record_id})")
        return record_id

    def delete_txt_record(self, record_id: str, **kwargs):
        self.client.delete(f"/domain/zone/{self.zone_name}/record/{record_id}")
        self.client.post(f"/domain/zone/{self.zone_name}/refresh")
        logger.info(f"DNS TXT deleted: {record_id}")

    def test_connection(self) -> dict:
        try:
            zone_info = self.client.get(f"/domain/zone/{self.zone_name}")
            return {"success": True, "message": f"Connected to OVHcloud zone: {zone_info.get('name', self.zone_name)}"}
        except Exception as e:
            return {"success": False, "message": str(e)}


def get_dns_provider(config: dict):
    """Factory function to create the appropriate DNS provider."""
    provider = config.get("dns_provider", "cloudflare").lower()
    if provider == "cloudflare":
        return CloudflareDNS(config)
    elif provider == "aws_route53":
        return AWSRoute53DNS(config)
    elif provider == "azure_dns":
        return AzureDNS(config)
    elif provider == "ovhcloud":
        return OVHCloudDNS(config)
    else:
        raise ValueError(f"Unsupported DNS provider: {provider}")
