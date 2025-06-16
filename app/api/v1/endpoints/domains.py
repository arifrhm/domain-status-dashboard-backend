from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.api.deps import get_current_active_user
from app.db.session import get_db
from app.models.domain import Domain
from app.models.user import User
from app.schemas.domain import (
    Domain as DomainSchema,
    DomainCreate,
    DomainCheckResult
)
from app.services.dns_checker import DNSChecker

router = APIRouter()


@router.post("/", response_model=DomainSchema)
async def create_domain(
    *,
    db: AsyncSession = Depends(get_db),
    domain_in: DomainCreate,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Create new domain for the current user.
    """
    # Check if domain already exists
    result = await db.execute(
        select(Domain).where(Domain.domain_name == domain_in.domain_name)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain already registered",
        )

    # Create domain and check DNS records
    domain = Domain(
        domain_name=domain_in.domain_name,
        user_id=current_user.id
    )
    
    # Check DNS records
    check_result = await DNSChecker.check_all(domain_in.domain_name)
    domain.dmarc_record = check_result["dmarc_record"]
    domain.dmarc_status = check_result["dmarc_status"]
    domain.spf_record = check_result["spf_record"]
    domain.spf_status = check_result["spf_status"]
    domain.dkim_record = check_result["dkim_record"]
    domain.dkim_status = check_result["dkim_status"]
    domain.set_mx_records(check_result["mx_records"])
    domain.mx_status = check_result["mx_status"]

    db.add(domain)
    await db.commit()
    await db.refresh(domain)
    return domain


@router.get("/", response_model=List[DomainSchema])
async def read_domains(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Retrieve domains for current user.
    """
    result = await db.execute(
        select(Domain).where(Domain.user_id == current_user.id)
    )
    domains = result.scalars().all()
    return domains


@router.get("/{domain_id}", response_model=DomainSchema)
async def read_domain(
    *,
    db: AsyncSession = Depends(get_db),
    domain_id: int,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get domain by ID.
    """
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id
        )
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    return domain


@router.post("/{domain_id}/check", response_model=DomainCheckResult)
async def check_domain(
    *,
    db: AsyncSession = Depends(get_db),
    domain_id: int,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Check domain DNS records and update results.
    
    This endpoint performs a fresh check of all DNS records for the specified domain:
    - DMARC record
    - SPF record
    - DKIM record
    - MX records
    
    The results are stored in the database and returned with detailed status information.
    """
    try:
        # Get domain
        result = await db.execute(
            select(Domain).where(
                Domain.id == domain_id,
                Domain.user_id == current_user.id
            )
        )
        domain = result.scalar_one_or_none()
        if not domain:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not found",
            )

        # Check DNS records
        check_result = await DNSChecker.check_all(domain.domain_name)
        print(check_result)
        # Update domain with new results
        domain.dmarc_record = check_result["dmarc_record"]
        domain.dmarc_status = check_result["dmarc_status"]
        domain.spf_record = check_result["spf_record"]
        domain.spf_status = check_result["spf_status"]
        domain.dkim_record = check_result["dkim_record"]
        domain.dkim_status = check_result["dkim_status"]
        domain.set_mx_records(check_result["mx_records"])
        domain.mx_status = check_result["mx_status"]

        await db.commit()
        await db.refresh(domain)
        
        return check_result
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 