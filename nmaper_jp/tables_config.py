from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, BLOB, DateTime


base = declarative_base()

class ConfigNmap(base):
    __tablename__ = 'config_nmap'
    id = Column(Integer, primary_key=True)
    property = Column(String(255), nullable=False)
    value = Column(String(255), nullable=False)


class NmapReportsDHCPDiscover(base):
    __tablename__ = 'nmap_reports_dhcp_discover'
    id = Column(Integer, primary_key=True)
    time = Column(DateTime)
    report = Column(BLOB)

class NmapReportsSnifferDetect(base):
    __tablename__ = 'nmap_reports_sniffer_detect'
    id = Column(Integer, primary_key=True)
    time = Column(DateTime)
    report = Column(BLOB)

class NmapDiff(base):
    __tablename__ = 'nmap_diff'
    id = Column(Integer, primary_key=True)
    result = Column(BLOB)