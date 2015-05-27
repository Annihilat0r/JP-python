from libnmap.parser import NmapParser

from jp_test import NmapWrapper
from nmaper_jp.tables_config import NmapDiff


class Diff:
    def __init__(self):
        self.diff = []

    def nested_obj(self,objname):
        '''
        Find a string for compare (NmapHost::127.0.0.1, NmapService::tcp.25, etc)
        :param objname: diff result, trying to go deeper
        :return: 'NmapHost' or 'NmapService'
        '''
        rval = None
        splitted = objname.split("::")
        if len(splitted) == 2:
            rval = splitted
        return rval


    def print_diff_added(self, obj1, obj2, added):
        for akey in added:
            nested = self.nested_obj(akey)
            if nested is not None:
                if nested[0] == 'NmapHost':
                    subobj1 = obj1.get_host_byid(nested[1])
                elif nested[0] == 'NmapService':
                    subobj1 = obj1.get_service_byid(nested[1])
                self.diff.append("+ {0}".format(subobj1))
            else:
                self.diff.append("+ {0} {1}: {2}".format(obj1, akey, getattr(obj1, akey)))


    def print_diff_removed(self, obj1, obj2, removed):
        for rkey in removed:
            nested = self.nested_obj(rkey)
            if nested is not None:
                if nested[0] == 'NmapHost':
                    subobj2 = obj2.get_host_byid(nested[1])
                elif nested[0] == 'NmapService':
                    subobj2 = obj2.get_service_byid(nested[1])
                self.diff.append("- {0}".format(subobj2))
            else:
                self.diff.append("- {0} {1}: {2}".format(obj2, rkey, getattr(obj2, rkey)))


    def print_diff_changed(self, obj1, obj2, changes):
        for mkey in changes:
            nested = self.nested_obj(mkey)
            if nested is not None:
                if nested[0] == 'NmapHost':
                    subobj1 = obj1.get_host_byid(nested[1])
                    subobj2 = obj2.get_host_byid(nested[1])
                elif nested[0] == 'NmapService':
                    subobj1 = obj1.get_service_byid(nested[1])
                    subobj2 = obj2.get_service_byid(nested[1])
                self.print_diff(subobj1, subobj2)
            else:
                self.diff.append("~ {0} {1}: {2} => {3}".format(obj1, mkey,
                                                     getattr(obj2, mkey),
                                                     getattr(obj1, mkey)))


    def print_diff(self, obj1, obj2):
        '''
        main logic
        :param obj1: first report
        :param obj2: second report
        :return: all printing in methods
        '''
        ndiff = obj1.diff(obj2)
        self.print_diff_changed(obj1, obj2, ndiff.changed())
        self.print_diff_added(obj1, obj2, ndiff.added())
        self.print_diff_removed(obj1, obj2, ndiff.removed())


    def diff_reports(self, first_rep=-1, second_rep=-2, fresh_scan=False, test_for_debug=False):
        '''
        Launcher for nmap_diff.
        :param first_rep: first report from DB
        :param second_rep: second report from DB
        :param fresh_scan: if we want to do a new scan before diff
        :param test_for_debug: just see how diff works with good XML NMAP reports
        :return:
        '''
        if test_for_debug:
            print('#################TEST_FOR_DEBUG#########################')
            newrep = NmapParser.parse_fromfile('C:\\Python34\\Lib\\site-packages\\libnmap\\test\\files\\2_hosts_achange.xml')
            oldrep = NmapParser.parse_fromfile('C:\\Python34\\Lib\\site-packages\\libnmap\\test\\files\\1_hosts.xml')
            self.print_diff(newrep, oldrep)
        else:
            nm = NmapWrapper()
            if fresh_scan:
                nm.launch()
            all_reports = nm.get_all_reports()
            rep1 = all_reports[first_rep][1]
            rep2 = all_reports[second_rep][1]
            self.print_diff(rep1, rep2)
        self.write_to_db(self.diff)

    def write_to_db(self, diff):
        session = self.nm.db_connect()
        str_confirm=''
        for i in range(len(self.diff)):
            str_confirm += ' '+ str(i) + '#'+self.diff[i]
        w = (bytes(str_confirm, 'utf-8'))
        session.add(NmapDiff(result=w))
        session.commit()

        #debug. delete for prod
        print('SELECT * FROM config_nmap')
        s = session.query(NmapDiff).all()
        for sa in s:
            print(sa.id, '=', sa.result)

    def main(self):
        '''
        What we will see in console
        :return: nothing
        '''
        self.nm = NmapWrapper()
        print('\n '
              'Welcome to nmap_diff \n '
              '1: Diff 2 last scan reports \n '
              '2: Do a fresh scan and diff with last report \n '
              '3: Choose a scan reports for diff \n '
              '4: Just show me a test diff \n '
              '5: Exit')
        chose = int(input())
        if chose == 1:
            self.diff_reports()
        if chose == 2:
            self.diff_reports(fresh_scan=True)
        if chose == 3:
            print('Input first report ID:')
            first = int(input())
            print('Input second report ID:')
            second = int(input())
            self.diff_reports(first, second)
        if chose == 4:
            self.diff_reports(test_for_debug=True)
        #if chose != 5:  yncomment for recursive work
        #    self.main()

        return self.diff

if __name__ == "__main__":
    diff = Diff()
    diff.main()
