import dns.resolver
from typing import Optional, List, Tuple, Dict
from datetime import datetime


class DNSChecker:
    @staticmethod
    async def check_dmarc(domain: str) -> Tuple[Optional[str], bool, Dict]:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                if "v=DMARC1" in str(rdata):
                    return str(rdata), True, {
                        "status": "valid",
                        "message": "DMARC record found"
                    }
            return None, False, {
                "status": "invalid",
                "message": "DMARC record not found or invalid"
            }
        except dns.resolver.NXDOMAIN:
            return None, False, {
                "status": "invalid",
                "message": "DMARC record does not exist"
            }
        except dns.resolver.NoAnswer:
            return None, False, {
                "status": "invalid",
                "message": "No DMARC record found"
            }
        except Exception as e:
            return None, False, {
                "status": "error",
                "message": f"Error checking DMARC: {str(e)}"
            }

    @staticmethod
    async def check_spf(domain: str) -> Tuple[Optional[str], bool, Dict]:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                if "v=spf1" in str(rdata):
                    return str(rdata), True, {
                        "status": "valid",
                        "message": "SPF record found"
                    }
            return None, False, {
                "status": "invalid",
                "message": "SPF record not found or invalid"
            }
        except dns.resolver.NXDOMAIN:
            return None, False, {
                "status": "invalid",
                "message": "Domain does not exist"
            }
        except dns.resolver.NoAnswer:
            return None, False, {
                "status": "invalid",
                "message": "No SPF record found"
            }
        except Exception as e:
            return None, False, {
                "status": "error",
                "message": f"Error checking SPF: {str(e)}"
            }

    @staticmethod
    async def check_dkim(
        domain: str,
        selector: str = "default"
    ) -> Tuple[Optional[str], bool, Dict]:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                if "v=DKIM1" in str(rdata):
                    return str(rdata), True, {
                        "status": "valid",
                        "message": "DKIM record found"
                    }
            return None, False, {
                "status": "invalid",
                "message": "DKIM record not found or invalid"
            }
        except dns.resolver.NXDOMAIN:
            return None, False, {
                "status": "invalid",
                "message": "DKIM record does not exist"
            }
        except dns.resolver.NoAnswer:
            return None, False, {
                "status": "invalid",
                "message": "No DKIM record found"
            }
        except Exception as e:
            return None, False, {
                "status": "error",
                "message": f"Error checking DKIM: {str(e)}"
            }

    @staticmethod
    async def check_mx(domain: str) -> Tuple[Optional[List[str]], bool, Dict]:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = [str(rdata.exchange) for rdata in answers]
            if mx_records:
                return mx_records, True, {
                    "status": "valid",
                    "message": "MX records found"
                }
            return None, False, {
                "status": "invalid",
                "message": "No MX records found"
            }
        except dns.resolver.NXDOMAIN:
            return None, False, {
                "status": "invalid",
                "message": "Domain does not exist"
            }
        except dns.resolver.NoAnswer:
            return None, False, {
                "status": "invalid",
                "message": "No MX records found"
            }
        except Exception as e:
            return None, False, {
                "status": "error",
                "message": f"Error checking MX: {str(e)}"
            }

    @staticmethod
    async def check_all(domain: str) -> dict:
        dmarc_record, dmarc_status, dmarc_info = await DNSChecker.check_dmarc(domain)
        spf_record, spf_status, spf_info = await DNSChecker.check_spf(domain)
        dkim_record, dkim_status, dkim_info = await DNSChecker.check_dkim(domain)
        mx_records, mx_status, mx_info = await DNSChecker.check_mx(domain)

        # Calculate overall status
        overall_status = all([
            dmarc_status,
            spf_status,
            dkim_status,
            mx_status
        ])

        # Create check summary
        check_summary = {
            "dmarc": dmarc_info,
            "spf": spf_info,
            "dkim": dkim_info,
            "mx": mx_info
        }

        return {
            "domain_name": domain,
            "check_timestamp": datetime.utcnow(),
            "dmarc_record": dmarc_record,
            "dmarc_status": dmarc_status,
            "spf_record": spf_record,
            "spf_status": spf_status,
            "dkim_record": dkim_record,
            "dkim_status": dkim_status,
            "mx_records": mx_records,
            "mx_status": mx_status,
            "overall_status": overall_status,
            "check_summary": check_summary
        } 