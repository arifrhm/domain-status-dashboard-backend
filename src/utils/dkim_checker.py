def check_dkim_record(domain, resolver=None):
    try:
        if resolver is None:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            resolver.timeout = 5.0
            resolver.lifetime = 5.0

        # Check for DKIM record
        records = resolver.resolve(f'default._domainkey.{domain}', 'TXT')
        dkim_record = None
        
        for record in records:
            for string in record.strings:
                decoded = string.decode()
                if decoded.startswith('v=DKIM1'):
                    dkim_record = decoded
                    break
            if dkim_record:
                break

        if not dkim_record:
            return {
                'exists': False,
                'valid': False,
                'record': None,
                'error': 'DKIM record does not exist'
            }

        return {
            'exists': True,
            'valid': True,
            'record': dkim_record,
            'error': None
        }
    except dns.resolver.NXDOMAIN:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': 'Domain does not exist'
        }
    except dns.resolver.NoAnswer:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': 'No DKIM record found'
        }
    except dns.resolver.Timeout:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': 'DNS query timed out'
        }
    except Exception as e:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': f'Error checking DKIM: {str(e)}'
        } 