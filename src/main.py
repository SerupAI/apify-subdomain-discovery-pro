"""
Subdomain Discovery Pro Actor
Main logic adapted from CloudSight infrastructure analysis
"""
import asyncio
import time
from typing import Dict, List, Set, Optional, Any
from apify import Actor
from rich.console import Console
from rich.progress import Progress, TaskID
from .subdomain_discovery import SubdomainDiscoverer
from .security_analyzer import SecurityAnalyzer
from .wordlists import get_wordlist
from .utils import validate_domain, normalize_domain

console = Console()

async def main() -> None:
    """Main actor entry point"""
    async with Actor:
        # Get actor input
        actor_input = await Actor.get_input() or {}
        
        # Validate required input
        domains = actor_input.get('domains', [])
        if not domains:
            await Actor.fail('No domains provided in input')
            return
            
        # Configuration from input
        config = {
            'wordlist_type': actor_input.get('subdomainWordlist', 'security_focused'),
            'custom_wordlist': actor_input.get('customWordlist', []),
            'include_security_analysis': actor_input.get('includeSecurityAnalysis', True),
            'include_infrastructure_detection': actor_input.get('includeInfrastructureDetection', True),
            'include_certificate_transparency': actor_input.get('includeCertificateTransparency', True),
            'max_concurrency': actor_input.get('maxConcurrency', 10),
            'request_delay': actor_input.get('requestDelay', 0.3),
            'include_inactive_subdomains': actor_input.get('includeInactiveSubdomains', False)
        }
        
        Actor.log.info(f"Starting subdomain discovery for {len(domains)} domains")
        Actor.log.info(f"Configuration: {config}")
        
        # Initialize components
        discoverer = SubdomainDiscoverer(config)
        analyzer = SecurityAnalyzer(config) if config['include_security_analysis'] else None
        
        # Process each domain
        total_results = []
        
        with Progress() as progress:
            main_task = progress.add_task("Processing domains...", total=len(domains))
            
            for domain in domains:
                try:
                    # Normalize domain (handles URLs, strips protocols, etc.)
                    normalized_domain = normalize_domain(domain)
                    
                    if not normalized_domain:
                        Actor.log.warning(f"Could not extract domain from input: {domain}")
                        continue
                    
                    if not validate_domain(normalized_domain):
                        Actor.log.warning(f"Invalid domain format after normalization: {domain} -> {normalized_domain}")
                        continue
                    
                    if normalized_domain != domain:
                        Actor.log.info(f"Normalized input '{domain}' to domain '{normalized_domain}'")
                    
                    Actor.log.info(f"Processing domain: {normalized_domain}")
                    progress.update(main_task, description=f"Processing {normalized_domain}")
                    
                    # Discover subdomains
                    domain_results = await process_single_domain(
                        normalized_domain, 
                        discoverer, 
                        analyzer, 
                        config,
                        progress
                    )
                    
                    total_results.extend(domain_results)
                    progress.advance(main_task)
                    
                except Exception as e:
                    Actor.log.error(f"Error processing domain {domain}: {e}")
                    continue
        
        # Save results to Apify dataset
        Actor.log.info(f"Saving {len(total_results)} subdomain results to dataset")
        await Actor.push_data(total_results)
        
        # Log summary
        Actor.log.info(f"Discovery completed. Found {len(total_results)} total subdomains across {len(domains)} domains")


async def process_single_domain(
    domain: str, 
    discoverer: SubdomainDiscoverer, 
    analyzer: Optional[SecurityAnalyzer],
    config: Dict,
    progress: Progress
) -> List[Dict[str, Any]]:
    """Process a single domain for subdomain discovery and analysis"""
    
    results = []
    start_time = time.time()
    
    try:
        # Step 1: Discover subdomains
        Actor.log.info(f"Discovering subdomains for {domain}")
        subdomains = await discoverer.discover_subdomains(domain)
        
        if not subdomains:
            Actor.log.warning(f"No subdomains found for {domain}")
            return []
        
        Actor.log.info(f"Found {len(subdomains)} subdomains for {domain}")
        
        # Step 2: Analyze each subdomain
        subdomain_task = progress.add_task(f"Analyzing subdomains for {domain}", total=len(subdomains))
        
        for subdomain in subdomains:
            try:
                result = {
                    'domain': domain,
                    'subdomain': subdomain,
                    'discovered_at': time.time(),
                    'discovery_method': subdomains[subdomain].get('method', 'unknown'),
                    'is_active': subdomains[subdomain].get('is_active', False),
                    'ip_addresses': subdomains[subdomain].get('ips', []),
                    'cname_record': subdomains[subdomain].get('cname', None)
                }
                
                # Add security analysis if enabled
                if analyzer and config['include_security_analysis']:
                    security_data = await analyzer.analyze_subdomain(subdomain)
                    result.update(security_data)
                
                results.append(result)
                progress.advance(subdomain_task)
                
                # Respect rate limiting
                await asyncio.sleep(config['request_delay'])
                
            except Exception as e:
                Actor.log.error(f"Error analyzing subdomain {subdomain}: {e}")
                continue
        
        progress.remove_task(subdomain_task)
        
        elapsed_time = time.time() - start_time
        Actor.log.info(f"Completed analysis for {domain} in {elapsed_time:.2f} seconds")
        
    except Exception as e:
        Actor.log.error(f"Error processing domain {domain}: {e}")
    
    return results