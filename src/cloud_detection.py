"""
Cloud Provider Detection
Adapted from CloudSight's infrastructure detection
"""
import asyncio
import dns.resolver
from typing import Dict, Any
from apify import Actor

class CloudProviderDetector:
    """Detect cloud providers and infrastructure"""
    
    def __init__(self):
        # Provider configurations adapted from CloudSight
        self.provider_configs = {
            "aws": {
                "asns": {'14618', '16509'},
                "mx_domains": {'.amazonses.com'},
                "ssl_issuers": {'amazon'},
                "headers": {'awselb', 'x-amz-waf-', 'server: amazons3'},
                "server_contains": {'amazon'},
                "via_contains": {'cloudfront'},
                "cname_domains": {'.elb.amazonaws.com', '.s3.amazonaws.com'},
            },
            "gcp": {
                "asns": {'15169', '396982'},
                "mx_domains": {'.google.com', '.googlemail.com'},
                "ssl_issuers": {'google trust services', 'gts ca'},
                "headers": {'server: gse'},
                "server_contains": {'gse'},
                "via_contains": {'google'},
                "cname_domains": {'.ghs.googlehosted.com'},
            },
            "azure": {
                "asns": {'8075', '8068', '8069'},
                "mx_domains": {'.mail.protection.outlook.com'},
                "ssl_issuers": {'microsoft', 'digicert'},
                "headers": {'x-azure-ref'},
                "server_contains": {'microsoft-iis', 'asp.net'},
                "via_contains": set(),
                "cname_domains": {'.trafficmanager.net', '.azurewebsites.net', '.azureedge.net'},
            }
        }
    
    async def detect_providers(self, subdomain: str) -> Dict[str, Any]:
        """Detect cloud providers for a subdomain"""
        
        detection_results = {
            'providers_detected': [],
            'provider_details': {},
            'infrastructure_type': 'unknown'
        }
        
        try:
            for provider, config in self.provider_configs.items():
                detected = await self._check_provider(subdomain, provider, config)
                if detected['detected']:
                    detection_results['providers_detected'].append(provider)
                    detection_results['provider_details'][provider] = detected
            
            # Determine infrastructure type
            if detection_results['providers_detected']:
                detection_results['infrastructure_type'] = 'cloud'
            
        except Exception as e:
            Actor.log.error(f"Error detecting providers for {subdomain}: {e}")
        
        return detection_results
    
    async def _check_provider(self, subdomain: str, provider: str, config: Dict) -> Dict[str, Any]:
        """Check if subdomain uses a specific cloud provider"""
        
        result = {
            'detected': False,
            'confidence': 0,
            'indicators': []
        }
        
        try:
            # Check CNAME records
            cname_detected = await self._check_cname_domains(subdomain, config.get('cname_domains', set()))
            if cname_detected:
                result['detected'] = True
                result['confidence'] += 40
                result['indicators'].append('CNAME record')
            
            # Additional checks can be added here (IP ranges, headers, etc.)
            
        except Exception as e:
            Actor.log.debug(f"Error checking {provider} for {subdomain}: {e}")
        
        return result
    
    async def _check_cname_domains(self, subdomain: str, cname_domains: set) -> bool:
        """Check if subdomain CNAME points to provider domains"""
        
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname_target = rdata.target.to_text().lower().rstrip('.')
                for domain_ending in cname_domains:
                    if cname_target.endswith(domain_ending):
                        return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            Actor.log.debug(f"Error checking CNAME for {subdomain}: {e}")
        
        return False