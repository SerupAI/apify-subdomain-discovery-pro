"""
Certificate Transparency Log Searcher
Enhanced subdomain discovery through CT logs
"""
import asyncio
import aiohttp
import json
from typing import Set, List
from apify import Actor

class CTLogSearcher:
    """Search Certificate Transparency logs for subdomains"""
    
    def __init__(self):
        self.ct_sources = [
            "https://crt.sh/",
            "https://certspotter.com/api/v0/certs",
            # Add more CT log sources as needed
        ]
    
    async def search_ct_logs(self, domain: str) -> Set[str]:
        """Search CT logs for subdomains of the given domain"""
        
        subdomains = set()
        
        try:
            # Search crt.sh
            crt_sh_results = await self._search_crt_sh(domain)
            subdomains.update(crt_sh_results)
            
            # Add more CT log sources here
            
        except Exception as e:
            Actor.log.error(f"Error searching CT logs for {domain}: {e}")
        
        return subdomains
    
    async def _search_crt_sh(self, domain: str) -> Set[str]:
        """Search crt.sh for subdomains"""
        
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            
                            # Parse subject alternative names
                            for name in name_value.split('\n'):
                                name = name.strip()
                                if name and name.endswith(f".{domain}"):
                                    # Remove wildcard prefix
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    
                                    subdomains.add(name)
        
        except Exception as e:
            Actor.log.debug(f"Error searching crt.sh for {domain}: {e}")
        
        return subdomains