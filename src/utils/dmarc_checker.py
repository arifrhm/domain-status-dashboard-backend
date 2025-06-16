import dns.resolver
import dns.exception


def check_dmarc_record(domain, resolver=None):
    try:
        if resolver is None:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            resolver.timeout = 5.0
            resolver.lifetime = 5.0
            resolver.tries = 3
            resolver.rotate = True

        # Check for DMARC record
        try:
            records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        except dns.resolver.NoAnswer:
            return {
                'exists': False,
                'valid': False,
                'record': None,
                'error': 'No DMARC record found'
            }

        dmarc_record = None
        
        for record in records:
            for string in record.strings:
                decoded = string.decode()
                if decoded.startswith('v=DMARC1'):
                    dmarc_record = decoded
                    break
            if dmarc_record:
                break

        if not dmarc_record:
            return {
                'exists': False,
                'valid': False,
                'record': None,
                'error': 'No DMARC record found'
            }

        return {
            'exists': True,
            'valid': True,
            'record': dmarc_record,
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
            'error': 'No DMARC record found'
        }
    except dns.resolver.Timeout:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': 'DNS query timed out'
        }
    except dns.exception.DNSException as e:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': f'DNS error: {str(e)}'
        }
    except Exception as e:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': f'Error checking DMARC: {str(e)}'
        }

def check_dkim(domain, selector='20230601'):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    
    try:
        dkim_record = f"{selector}._domainkey.{domain}"
        answers = resolver.resolve(dkim_record, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith('v=DKIM1'):
                    return {
                        'exists': True,
                        'valid': True,
                        'record': decoded,
                        'error': None
                    }
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': 'No DKIM record found'
        }
    except Exception as e:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'error': f'Error checking DKIM: {str(e)}'
        } 