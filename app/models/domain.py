from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import json
from app.models.user import Base

class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Email security check results
    dmarc_record = Column(String, nullable=True)
    dmarc_status = Column(Boolean, nullable=True)
    spf_record = Column(String, nullable=True)
    spf_status = Column(Boolean, nullable=True)
    dkim_record = Column(String, nullable=True)
    dkim_status = Column(Boolean, nullable=True)
    mx_records = Column(String, nullable=True)  # Stored as JSON string
    mx_status = Column(Boolean, nullable=True)

    # Relationship
    user = relationship("User", back_populates="domains")

    def set_mx_records(self, records: list):
        """Set MX records as a JSON string."""
        if records is not None:
            self.mx_records = json.dumps(records)
        else:
            self.mx_records = None

    def get_mx_records(self) -> list:
        """Get MX records as a list."""
        if self.mx_records:
            return json.loads(self.mx_records)
        return None 