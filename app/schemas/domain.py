from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, HttpUrl, validator


class DomainBase(BaseModel):
    domain_name: str

    @validator('domain_name')
    def validate_domain_name(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Domain name must be at least 3 characters long')
        if ' ' in v:
            raise ValueError('Domain name cannot contain spaces')
        return v.lower()


class DomainCreate(DomainBase):
    pass


class DomainUpdate(DomainBase):
    pass


class DomainInDBBase(DomainBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime
    dmarc_record: Optional[str] = None
    dmarc_status: Optional[bool] = None
    spf_record: Optional[str] = None
    spf_status: Optional[bool] = None
    dkim_record: Optional[str] = None
    dkim_status: Optional[bool] = None
    mx_records: Optional[str] = None
    mx_status: Optional[bool] = None

    class Config:
        from_attributes = True


class Domain(DomainInDBBase):
    pass


class DomainCheckResult(BaseModel):
    domain_name: str
    check_timestamp: datetime
    dmarc_record: Optional[str] = None
    dmarc_status: Optional[bool] = None
    spf_record: Optional[str] = None
    spf_status: Optional[bool] = None
    dkim_record: Optional[str] = None
    dkim_status: Optional[bool] = None
    mx_records: Optional[List[str]] = None
    mx_status: Optional[bool] = None
    overall_status: bool
    check_summary: dict

    class Config:
        from_attributes = True 