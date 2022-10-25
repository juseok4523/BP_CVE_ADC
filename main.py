from csv import excel
from multiprocessing import set_forkserver_preload
from select import select
from weakref import ref
import numpy as np
import pandas as pd
from pyExploitDb import PyExploitDb
import csv


class BP_CVE(PyExploitDb):
    def __init__(self):
        super().__init__()
        self.bp_df = None
        self.debug = False
        self.openFile()
        
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
        #print(select_df[select_df['Exploit'] != ''])
        return select_df
        
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
        
        return ''
        
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
        


def main():
    bp_cve = BP_CVE()
    #test
    bp_cve.read_Excel('data/TA-BP-CVE-TEST-attack_report-2022.07-arrange-jk.xlsx', 'arrange-jk')
    ex_df = bp_cve.select_exploitdb()
    #product
    return

if __name__ == "__main__":
    main()