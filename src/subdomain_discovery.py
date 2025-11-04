"""
Subdomain Discovery Engine
Adapted from CloudSight's domain enumeration capabilities with security enhancements
"""
import asyncio
import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype
import ssl
import socket
from typing import Dict, List, Set, Optional, Any
from apify import Actor
from .wordlists import get_wordlist
from .certificate_transparency import CTLogSearcher
from .utils import is_valid_subdomain

class SubdomainDiscoverer:
    """Enhanced subdomain discovery using multiple techniques"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.wordlist = get_wordlist(config['wordlist_type'], config.get('custom_wordlist', []))
        self.ct_searcher = CTLogSearcher() if config['include_certificate_transparency'] else None
        self.max_concurrency = config['max_concurrency']
        self.request_delay = config['request_delay']
        
    async def discover_subdomains(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Main subdomain discovery method combining multiple techniques"""
        
        Actor.log.info(f"Starting subdomain discovery for {domain}")
        discovered = {}
        
        # Method 1: Wordlist-based enumeration (adapted from CloudSight's COMMON_SUBDOMAINS)
        Actor.log.info(f"Method 1: Wordlist enumeration with {len(self.wordlist)} subdomains")
        wordlist_results = await self._wordlist_enumeration(domain)
        discovered.update(wordlist_results)
        
        # Method 2: Certificate Transparency logs (new addition)
        if self.ct_searcher:
            Actor.log.info("Method 2: Certificate Transparency log search")
            ct_results = await self._certificate_transparency_search(domain)
            discovered.update(ct_results)
        
        # Method 3: DNS zone transfer attempt (security-focused)
        Actor.log.info("Method 3: DNS zone transfer attempt")
        zone_transfer_results = await self._zone_transfer_attempt(domain)
        discovered.update(zone_transfer_results)
        
        # Method 4: Reverse DNS lookup on discovered IPs
        Actor.log.info("Method 4: Reverse DNS analysis")
        reverse_dns_results = await self._reverse_dns_analysis(domain, discovered)
        discovered.update(reverse_dns_results)
        
        # Filter results based on configuration
        if not self.config['include_inactive_subdomains']:
            discovered = {k: v for k, v in discovered.items() if v.get('is_active', False)}
        
        Actor.log.info(f"Discovery completed. Found {len(discovered)} subdomains for {domain}")
        return discovered
    
    async def _wordlist_enumeration(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Wordlist-based subdomain enumeration (adapted from CloudSight)"""
        
        discovered = {}
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async def check_subdomain(subdomain_prefix: str):
            async with semaphore:
                try:
                    subdomain = f"{subdomain_prefix}.{domain}"
                    
                    if not is_valid_subdomain(subdomain):
                        return
                    
                    # DNS resolution (adapted from CloudSight's check_provider_ip_asn)
                    result = await self._resolve_subdomain(subdomain)
                    
                    if result:
                        discovered[subdomain] = {
                            'method': 'wordlist',
                            'prefix': subdomain_prefix,
                            **result
                        }
                    
                    # Rate limiting
                    await asyncio.sleep(self.request_delay)
                    
                except Exception as e:
                    Actor.log.debug(f"Error checking subdomain {subdomain_prefix}.{domain}: {e}")
        
        # Process wordlist concurrently
        tasks = [check_subdomain(prefix) for prefix in self.wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return discovered
    
    async def _resolve_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """Resolve subdomain to IPs and get additional DNS info (adapted from CloudSight)"""
        
        result = {
            'is_active': False,
            'ips': [],
            'cname': None,
            'mx_records': [],
            'txt_records': [],
            'ns_records': []
        }
        
        try:
            # Check for CNAME first (from CloudSight's ip check logic)
            try:
                cname_answers = dns.resolver.resolve(subdomain, 'CNAME')
                if cname_answers:
                    result['cname'] = cname_answers[0].target.to_text().rstrip('.')
                    subdomain_to_resolve = result['cname']
                else:
                    subdomain_to_resolve = subdomain
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                subdomain_to_resolve = subdomain
            
            # A record resolution
            try:
                a_answers = dns.resolver.resolve(subdomain_to_resolve, 'A')
                result['ips'].extend([rdata.address for rdata in a_answers])
                result['is_active'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # AAAA record resolution
            try:
                aaaa_answers = dns.resolver.resolve(subdomain_to_resolve, 'AAAA')
                result['ips'].extend([rdata.address for rdata in aaaa_answers])
                result['is_active'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Additional DNS records for security analysis
            if result['is_active']:
                # MX records
                try:
                    mx_answers = dns.resolver.resolve(subdomain, 'MX')
                    result['mx_records'] = [rdata.exchange.to_text().rstrip('.') for rdata in mx_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                
                # TXT records (often contain security-relevant info)
                try:
                    txt_answers = dns.resolver.resolve(subdomain, 'TXT')
                    result['txt_records'] = [rdata.to_text() for rdata in txt_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                
                # NS records
                try:
                    ns_answers = dns.resolver.resolve(subdomain, 'NS')
                    result['ns_records'] = [rdata.target.to_text().rstrip('.') for rdata in ns_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
        
        except Exception as e:
            Actor.log.debug(f"Error resolving {subdomain}: {e}")
            return None
        
        return result if result['is_active'] or self.config['include_inactive_subdomains'] else None
    
    async def _certificate_transparency_search(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Search Certificate Transparency logs for subdomains"""
        
        discovered = {}
        
        try:
            ct_subdomains = await self.ct_searcher.search_ct_logs(domain)
            
            for subdomain in ct_subdomains:
                if subdomain not in discovered:
                    # Resolve the subdomain found in CT logs
                    result = await self._resolve_subdomain(subdomain)
                    if result:
                        discovered[subdomain] = {
                            'method': 'certificate_transparency',
                            **result
                        }
        
        except Exception as e:
            Actor.log.error(f"Error searching Certificate Transparency logs: {e}")
        
        return discovered
    
    async def _zone_transfer_attempt(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Attempt DNS zone transfer (security research technique)"""
        
        discovered = {}
        
        try:
            # Get authoritative name servers
            ns_answers = dns.resolver.resolve(domain, 'NS')
            name_servers = [rdata.target.to_text().rstrip('.') for rdata in ns_answers]
            
            for ns in name_servers:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    
                    for name, node in zone.nodes.items():
                        if name != dns.name.empty:
                            subdomain = f"{name}.{domain}"
                            
                            # Extract IP addresses from zone data
                            ips = []
                            for rdataset in node.rdatasets:
                                if rdataset.rdtype == dns.rdatatype.A:
                                    ips.extend([rdata.address for rdata in rdataset])
                                elif rdataset.rdtype == dns.rdatatype.AAAA:
                                    ips.extend([rdata.address for rdata in rdataset])
                            
                            if subdomain not in discovered:
                                discovered[subdomain] = {
                                    'method': 'zone_transfer',
                                    'is_active': len(ips) > 0,
                                    'ips': ips,
                                    'name_server': ns
                                }
                
                except Exception as e:
                    # Zone transfer failed (expected for most domains)
                    Actor.log.debug(f"Zone transfer failed for {domain} on {ns}: {e}")
                    continue
        
        except Exception as e:
            Actor.log.debug(f"Error attempting zone transfer for {domain}: {e}")
        
        return discovered
    
    async def _reverse_dns_analysis(self, domain: str, existing_subdomains: Dict) -> Dict[str, Dict[str, Any]]:
        """Perform reverse DNS lookups on discovered IPs to find additional subdomains"""
        
        discovered = {}
        
        # Collect all IPs from existing discoveries
        all_ips = set()
        for subdomain_data in existing_subdomains.values():
            all_ips.update(subdomain_data.get('ips', []))
        
        for ip in all_ips:
            try:
                # Reverse DNS lookup
                hostname = socket.gethostbyaddr(ip)[0]
                
                # Check if the hostname is a subdomain of our target domain
                if hostname.endswith(f".{domain}") and hostname not in existing_subdomains:
                    result = await self._resolve_subdomain(hostname)
                    if result:
                        discovered[hostname] = {
                            'method': 'reverse_dns',
                            'source_ip': ip,
                            **result
                        }
            
            except Exception as e:
                Actor.log.debug(f"Reverse DNS failed for {ip}: {e}")
                continue
        
        return discovered