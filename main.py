from heapq import merge
import numpy as np
import pandas as pd
from pyExploitDb import PyExploitDb
import csv
import re
from scapy.all import *
from scapy.layers import http


class BP_CVE(PyExploitDb):
    def __init__(self):
        super().__init__()
        self.bp_df = None
        self.debug = False
        self.pcap_packet = {}
        self.openFile()
        
        self.read_pcap()
        
    def read_pcap(self):
        print("Read pcap file...")
        conf.contribs["http"]["auto_compression"] = False
        pkts = sniff(offline="./data/tcpdump/S1E1.pcap", session=TCPSession)
        req = [p for p in pkts if p.haslayer(http.HTTPRequest)]
        for pkt in req:
            try:
                src = pkt['IP'].src
                dst = pkt['IP'].dst
                sport = pkt['TCP'].sport
                dport = pkt['TCP'].dport
                key = f'{src}:{sport}->{dst}:{dport}'
                value = pkt
                if key in self.pcap_packet:
                    temp = self.pcap_packet[key]
                    temp.append(value)
                    self.pcap_packet[key] = temp
                else :
                    self.pcap_packet[key] = list(value)
            except:
                continue
        print('Done read pcap')
            
        
    def searchCve(self, cveSearch):
        if not cveSearch:
            return []
        cveSearch = cveSearch.upper()
        #print(cveSearch)
        if cveSearch in self.cveToExploitMap:
            if self.debug == True:
                print("Found")
            cveData = self.getCveDetails(cveSearch)
            if cveData:
                return cveData
            else:
                return cveSearch
        return []

    def read_Excel(self, filename, sheet_name):
        excel_df = pd.read_excel(filename,
                             index_col=None, 
                             sheet_name=sheet_name, 
                             engine="openpyxl")
        
        #select data
        excel_df = excel_df[excel_df['Strike Result'] == 'Allowed']
        # remove col
        excel_df = excel_df.drop(columns=['Strike Result', 'Permutations'])
        # rename col
        excel_df = excel_df.rename(columns={'Time of strike':'Time', 'Strike Name':'Name', 'Strike Reference':'Reference', 'Strike Tuples':'Network'})
        self.bp_df = excel_df.sort_values('Time').reset_index(drop=True)
        #print(self.bp_df) #debug
        return
    
    def select_exploitdb(self):
        select_df = self.bp_df[self.bp_df['Reference'].str.contains('CVE|ExploitDb|www.exploit-db.com/exploits/', na=False)].reset_index(drop=False)
        select_df['Exploit'] = select_df['Reference'].apply(self.get_Exploit)
        #print(select_df[!isnan(select_df['Exploit'])])
        return select_df[['index', 'Exploit']]
        
    def get_Exploit(self, x): 
        filename = []
        if "ExploitDb" in x :
            Exploit_num = x.split('ExploitDb')[1].split()[0]
            filename = self.getExploitDetails(Exploit_num)['exploit']
        
        elif "www.exploit-db.com/exploits/" in x:
            Exploit_num = x.split('www.exploit-db.com/exploits/')[1].split('/')[0].split()[0]
            filename = self.getExploitDetails(Exploit_num)['exploit']
                
        elif "CVE" in x:
            Exploit_num = 'CVE-'+ x.split('CVE')[1].split()[0]
            result = self.searchCve(Exploit_num)
            if len(result) != 0:
                filename = result['exploit']
                
        if len(filename) != 0:
            filename = filename.replace('\\', '\\\\')
            with open(filename, 'r', encoding='UTF8') as f:
                exploit = f.read()
                return exploit
        
        return np.NaN
        
    def getExploitDetails(self, num):
        files = open(self.currentPath + "/exploit-database/files_exploits.csv", encoding="utf-8")
        reader = csv.reader(files)
        next(reader)
        result = {}
        for row in reader:
            edb, fileName, description, date, author, platform, exploitType, port = tuple(row)
            if edb == num :
                found = True
                result['edbid'] = edb
                result['exploit'] = self.exploitDbPath + "/" + fileName
        files.close()
        return result
        
    def select_pcap(self): 
        net_df = self.bp_df['Network'].to_frame()
        net_df['Net_Exploit'] = net_df['Network'].apply(self.get_Network_Exploit)
        #print(net_df)
        return net_df
    
    def get_Network_Exploit(self, x):
        x_list = re.split('TCP|HTTP|IP', x)
        xx_list = []
        for x in x_list:
            for y in x.split():
                xx_list.append(y)
        result = ""
        for xx in xx_list:
            if xx in self.pcap_packet:
                pkts = self.pcap_packet[xx]
                for pkt in pkts:
                    temp = str(pkt['HTTPRequest'])[2:-1].replace('\\r\\n', '\n')
                    #print(temp)
                    result += temp+'----------------------------------\n'
        return str(result)

    def merge_df(self, ex, net):
        merge_df = pd.merge(self.bp_df, ex, left_index=True, right_on='index', how='left').reset_index(drop=True).drop(columns='index')
        merge_df = pd.merge(merge_df, net, on='Network')
        self.bp_df = merge_df
        return

    
def main():
    bp_cve = BP_CVE()
    #test
    bp_cve.read_Excel('data/TA-BP-CVE-TEST-attack_report-2022.07-arrange-jk.xlsx', 'arrange-jk')
    ex_df = bp_cve.select_exploitdb()
    net_df = bp_cve.select_pcap()
    bp_cve.merge_df(ex_df, net_df)
    #product
    return

if __name__ == "__main__":
    main()