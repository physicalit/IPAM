from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Float
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)


class Subnet(Base):
    __tablename__ = "subnet"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    notes = Column(String, nullable=True)

    hosts = relationship("Host", back_populates="subnet")


class Host(Base):
    __tablename__ = "host"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, nullable=False)
    subnet_id = Column(Integer, ForeignKey("subnet.id"))
    hostname = Column(String, nullable=True)
    description = Column(String, nullable=True)
    tags_json = Column(String, nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    subnet = relationship("Subnet", back_populates="hosts")
    statuses = relationship("HostStatus", back_populates="host", order_by="desc(HostStatus.ts)")
    open_ports = relationship("HostOpenPort", back_populates="host", order_by="desc(HostOpenPort.ts)")


class HostStatus(Base):
    __tablename__ = "host_status"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"), index=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)
    is_up = Column(Boolean, default=False)
    latency_ms = Column(Float, nullable=True)

    host = relationship("Host", back_populates="statuses")


class HostOpenPort(Base):
    __tablename__ = "host_open_port"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"), index=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)
    port = Column(Integer, nullable=False)
    proto = Column(String, default="tcp")
    service = Column(String, nullable=True)
    state = Column(String, nullable=True)

    host = relationship("Host", back_populates="open_ports")
