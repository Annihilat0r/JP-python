from  nmaper_jp import *

def main():
    print('\n '
              'Welcome to jp_test \n '
              '1: Do scan \n '
              '2: Get one report from DB \n '
              '3: Get all reports from DB \n '
              '4: Config DB for nmap parameters (127.0.0.1 20-443) \n '
              '5: Config DB for nmap parameters for prod (get external IP) \n '
              '6: Start nmap diff \n '
              '7: Sniffer detect \n '
              '8: DHCP discover \n '
              '9: Brutforce \n '
              '99: Exit')
    chose = int(input())
    if chose == 1:
        print(nm.launch()) #For start scan
    if chose == 2:
        print('Write a number of report:')
        a = input()
        print(nm.get_report(a, True)) #get report #1
    if chose == 3:
        print(nm.get_all_reports(True)) #get all reports raw_data
    if chose == 4:
        first_start(prod=False)
    if chose == 5:
        first_start(prod=True)
    if chose == 6:
        diff.main()
    if chose == 7:
        sniffer_detect_lunch()
    if chose == 8:
        DHCP_discover()
    if chose == 9:
        brute = Patator()
        print('Write ip-address for bruteforce')
        ip_for_brute = input()
        brute.launch("ssh_login", ip_for_brute)
    if chose != 99:  # do comment for cancel recursive work
        main()


if __name__ == "__main__":
    nm = NmapWrapper()
    main()