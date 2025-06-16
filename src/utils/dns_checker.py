import dns.resolver
import dns.exception
import spf
from datetime import datetime
from app.core.config import settings
from .dmarc_checker import check_dmarc_record
from .dkim_checker import check_dkim_record
from .mx_checker import check_mx_record


# Configure DNS resolver to use settings
resolver = dns.resolver.Resolver()
resolver.nameservers = settings.DNS_NAMESERVER_LIST
resolver.timeout = settings.DNS_TIMEOUT
resolver.lifetime = settings.DNS_LIFETIME
resolver.tries = settings.DNS_TRIES
resolver.rotate = True


def check_spf_record(domain):
    # Use Google's public IP and a dummy sender/helo for the check
    ip = '8.8.8.8'
    sender = f'test@{domain}'
    helo = domain
    try:
        result, explanation = spf.check2(i=ip, s=sender, h=helo)
        # Try to fetch the actual SPF record for reporting
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            spf_record = None
            for record in txt_records:
                for string in record.strings:
                    decoded = string.decode()
                    if decoded.startswith('v=spf1'):
                        spf_record = decoded
                        break
                if spf_record:
                    break
        except Exception:
            spf_record = None
        return {
            'exists': True if result != 'none' else False,
            'valid': result == 'pass',
            'record': spf_record,
            'status': result,
            'explanation': explanation,
            'error': None
        }
    except Exception as e:
        return {
            'exists': False,
            'valid': False,
            'record': None,
            'status': 'error',
            'explanation': str(e),
            'error': f'Error checking SPF: {str(e)}'
        }


def check_domain(domain):
    try:
        check_timestamp = datetime.utcnow()
        
        dmarc_result = check_dmarc_record(domain, resolver)
        spf_result = check_spf_record(domain)
        dkim_result = check_dkim_record(domain, resolver)
        mx_result = check_mx_record(domain, resolver)

        # Determine overall status
        overall_status = (
            dmarc_result['valid'] and 
            spf_result['valid'] and 
            dkim_result['valid'] and 
            mx_result['valid']
        )

        # Create check summary
        check_summary = {
            'dmarc': {
                'status': 'valid' if dmarc_result['valid'] else 'invalid',
                'message': (
                    'DMARC record found' if dmarc_result['valid']
                    else dmarc_result['error']
                )
            },
            'spf': {
                'status': spf_result['status'],
                'message': spf_result['explanation']
            },
            'dkim': {
                'status': 'valid' if dkim_result['valid'] else 'invalid',
                'message': (
                    'DKIM record found' if dkim_result['valid']
                    else dkim_result['error']
                )
            },
            'mx': {
                'status': 'valid' if mx_result['valid'] else 'invalid',
                'message': (
                    'MX records found' if mx_result['valid']
                    else mx_result['error']
                )
            }
        }

        return {
            'domain_name': domain,
            'check_timestamp': check_timestamp,
            'dmarc_record': dmarc_result['record'],
            'dmarc_status': dmarc_result['valid'],
            'spf_record': spf_result['record'],
            'spf_status': spf_result['valid'],
            'dkim_record': dkim_result['record'],
            'dkim_status': dkim_result['valid'],
            'mx_records': mx_result['record'] if mx_result['record'] else [],
            'mx_status': mx_result['valid'],
            'overall_status': overall_status,
            'check_summary': check_summary
        }
    except Exception as e:
        return {
            'domain_name': domain,
            'check_timestamp': datetime.utcnow(),
            'error': str(e),
            'overall_status': False
        } 