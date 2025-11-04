"""
Security Analysis Engine
Adapted from CloudSight's infrastructure analysis with security enhancements
"""
import asyncio
import ssl
import socket
import requests
from typing import Dict, List, Optional, Any
from apify import Actor
from .cloud_detection import CloudProviderDetector
from .vulnerability_scanner import VulnerabilityScanner

class SecurityAnalyzer:
    """Enhanced security analysis for discovered subdomains"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.cloud_detector = CloudProviderDetector() if config['include_infrastructure_detection'] else None
        self.vuln_scanner = VulnerabilityScanner()
        
    async def analyze_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Comprehensive security analysis of a subdomain"""
        
        Actor.log.debug(f"Analyzing security for {subdomain}")
        
        analysis = {
            'security_analysis': {
                'analyzed_at': asyncio.get_event_loop().time(),
                'ssl_analysis': {},
                'http_analysis': {},
                'infrastructure_analysis': {},
                'vulnerability_scan': {},
                'security_score': 0,
                'risk_level': 'unknown'
            }
        }
        
        try:
            # SSL/TLS Analysis (adapted from CloudSight's check_provider_ssl)
            analysis['security_analysis']['ssl_analysis'] = await self._analyze_ssl(subdomain)
            
            # HTTP Headers and Response Analysis (adapted from CloudSight's check_provider_headers)
            analysis['security_analysis']['http_analysis'] = await self._analyze_http(subdomain)
            
            # Infrastructure Detection (from CloudSight)
            if self.cloud_detector:
                analysis['security_analysis']['infrastructure_analysis'] = await self._detect_infrastructure(subdomain)
            
            # Vulnerability Scanning
            analysis['security_analysis']['vulnerability_scan'] = await self._scan_vulnerabilities(subdomain)
            
            # Calculate security score
            analysis['security_analysis']['security_score'] = self._calculate_security_score(analysis['security_analysis'])
            analysis['security_analysis']['risk_level'] = self._determine_risk_level(analysis['security_analysis']['security_score'])
            
        except Exception as e:
            Actor.log.error(f"Error during security analysis of {subdomain}: {e}")
            analysis['security_analysis']['error'] = str(e)
        
        return analysis
    
    async def _analyze_ssl(self, subdomain: str) -> Dict[str, Any]:
        """SSL/TLS certificate analysis (adapted from CloudSight)"""
        
        ssl_analysis = {
            'has_ssl': False,
            'certificate_valid': False,
            'certificate_info': {},
            'ssl_vulnerabilities': [],
            'security_headers': {}
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect and get certificate
            with socket.create_connection((subdomain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    ssl_analysis['has_ssl'] = True
                    ssl_analysis['certificate_valid'] = True
                    
                    # Get certificate details
                    cert = ssock.getpeercert()
                    ssl_analysis['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])]
                    }
                    
                    # Check for SSL vulnerabilities
                    ssl_analysis['ssl_vulnerabilities'] = self._check_ssl_vulnerabilities(ssock)
        
        except ssl.SSLError as e:
            ssl_analysis['ssl_error'] = str(e)
            Actor.log.debug(f"SSL error for {subdomain}: {e}")
        except Exception as e:
            ssl_analysis['connection_error'] = str(e)
            Actor.log.debug(f"Connection error for {subdomain}: {e}")
        
        return ssl_analysis
    
    async def _analyze_http(self, subdomain: str) -> Dict[str, Any]:
        """HTTP headers and response analysis (adapted from CloudSight)"""
        
        http_analysis = {
            'accessible': False,
            'status_code': None,
            'security_headers': {},
            'server_info': {},
            'cookies': [],
            'security_issues': []
        }
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{subdomain}"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (SecurityScanner/1.0; +https://example.com/bot)'
                }
                
                response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
                
                http_analysis['accessible'] = True
                http_analysis['status_code'] = response.status_code
                http_analysis['final_url'] = response.url
                http_analysis['protocol'] = protocol
                
                # Analyze security headers
                security_headers = self._analyze_security_headers(response.headers)
                http_analysis['security_headers'] = security_headers
                
                # Server information
                http_analysis['server_info'] = {
                    'server': response.headers.get('Server', ''),
                    'x_powered_by': response.headers.get('X-Powered-By', ''),
                    'technology_stack': self._detect_technology_stack(response)
                }
                
                # Cookie analysis
                http_analysis['cookies'] = self._analyze_cookies(response.cookies)
                
                # Identify security issues
                http_analysis['security_issues'] = self._identify_security_issues(response)
                
                break  # Success, no need to try other protocols
                
            except requests.exceptions.RequestException as e:
                Actor.log.debug(f"HTTP request failed for {protocol}://{subdomain}: {e}")
                continue
        
        return http_analysis
    
    async def _detect_infrastructure(self, subdomain: str) -> Dict[str, Any]:
        """Infrastructure and cloud provider detection (from CloudSight)"""
        
        if not self.cloud_detector:
            return {}
        
        return await self.cloud_detector.detect_providers(subdomain)
    
    async def _scan_vulnerabilities(self, subdomain: str) -> Dict[str, Any]:
        """Basic vulnerability scanning"""
        
        return await self.vuln_scanner.scan_subdomain(subdomain)
    
    def _analyze_security_headers(self, headers: Dict) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        
        security_headers = {
            'strict_transport_security': headers.get('Strict-Transport-Security'),
            'content_security_policy': headers.get('Content-Security-Policy'),
            'x_frame_options': headers.get('X-Frame-Options'),
            'x_content_type_options': headers.get('X-Content-Type-Options'),
            'x_xss_protection': headers.get('X-XSS-Protection'),
            'referrer_policy': headers.get('Referrer-Policy'),
            'permissions_policy': headers.get('Permissions-Policy'),
        }
        
        # Calculate security header score
        present_headers = sum(1 for v in security_headers.values() if v)
        security_headers['score'] = present_headers / len(security_headers) * 100
        security_headers['missing_headers'] = [k for k, v in security_headers.items() if not v]
        
        return security_headers
    
    def _detect_technology_stack(self, response: requests.Response) -> List[str]:
        """Detect technology stack from HTTP response"""
        
        technologies = []
        
        # Server header analysis
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # X-Powered-By analysis
        powered_by = response.headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Content analysis (basic detection)
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append('WordPress')
        elif 'drupal' in content:
            technologies.append('Drupal')
        
        return technologies
    
    def _analyze_cookies(self, cookies) -> List[Dict]:
        """Analyze cookies for security issues"""
        
        cookie_analysis = []
        
        for cookie in cookies:
            analysis = {
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': hasattr(cookie, 'httponly') and cookie.httponly,
                'samesite': getattr(cookie, 'samesite', None),
                'issues': []
            }
            
            if not cookie.secure:
                analysis['issues'].append('Missing Secure flag')
            if not (hasattr(cookie, 'httponly') and cookie.httponly):
                analysis['issues'].append('Missing HttpOnly flag')
            if not getattr(cookie, 'samesite', None):
                analysis['issues'].append('Missing SameSite attribute')
            
            cookie_analysis.append(analysis)
        
        return cookie_analysis
    
    def _identify_security_issues(self, response: requests.Response) -> List[str]:
        """Identify common security issues"""
        
        issues = []
        
        # Check for information disclosure
        if 'server' in response.headers and any(keyword in response.headers['server'].lower() 
                                               for keyword in ['apache/2.', 'nginx/1.', 'iis/7.']):
            issues.append('Server version disclosure')
        
        # Check for directory listing
        if 'index of /' in response.text.lower():
            issues.append('Potential directory listing')
        
        # Check for common admin panels
        if any(keyword in response.text.lower() for keyword in ['admin login', 'administrator', 'phpmyadmin']):
            issues.append('Admin panel detected')
        
        # Check for error messages
        if any(keyword in response.text.lower() for keyword in ['mysql error', 'php warning', 'stack trace']):
            issues.append('Error message disclosure')
        
        return issues
    
    def _check_ssl_vulnerabilities(self, ssl_socket) -> List[str]:
        """Check for SSL/TLS vulnerabilities"""
        
        vulnerabilities = []
        
        try:
            # Get SSL version
            ssl_version = ssl_socket.version()
            
            # Check for outdated SSL/TLS versions
            if ssl_version in ['SSLv2', 'SSLv3']:
                vulnerabilities.append(f'Outdated SSL version: {ssl_version}')
            elif ssl_version == 'TLSv1':
                vulnerabilities.append('TLS 1.0 is deprecated')
            elif ssl_version == 'TLSv1.1':
                vulnerabilities.append('TLS 1.1 is deprecated')
        
        except Exception as e:
            Actor.log.debug(f"Error checking SSL vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _calculate_security_score(self, analysis: Dict) -> int:
        """Calculate overall security score (0-100)"""
        
        score = 0
        max_score = 100
        
        # SSL score (30 points)
        ssl_data = analysis.get('ssl_analysis', {})
        if ssl_data.get('has_ssl'):
            score += 15
            if ssl_data.get('certificate_valid'):
                score += 10
            if not ssl_data.get('ssl_vulnerabilities'):
                score += 5
        
        # HTTP security headers score (40 points)
        http_data = analysis.get('http_analysis', {})
        headers_score = http_data.get('security_headers', {}).get('score', 0)
        score += int(headers_score * 0.4)
        
        # Vulnerability scan score (30 points)
        vuln_data = analysis.get('vulnerability_scan', {})
        vuln_count = len(vuln_data.get('vulnerabilities', []))
        if vuln_count == 0:
            score += 30
        elif vuln_count <= 2:
            score += 20
        elif vuln_count <= 5:
            score += 10
        
        return min(score, max_score)
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on security score"""
        
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'