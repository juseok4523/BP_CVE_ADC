import numpy as np
import pandas as pd
from pyExploitDb import PyExploitDb
import csv
import re
from scapy.all import *
from scapy.layers import http
import sqlalchemy
from sqlalchemy import create_engine
import requests
from bs4 import BeautifulSoup as bs
import multiprocessing as mp
import argparse
from warnings import filterwarnings
from datetime import datetime
import git
import json
filterwarnings("ignore")

class BP_CVE(PyExploitDb):
    def __init__(self):
        super().__init__()
        self.bp_df = None
        self.debug = False
        self.pcap_packet = {}
        self.openFile()
        self.read_pcap()
        self.get_PoC()
    
    #overriding func
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
        
    def getCveDetails(self, cveSearch):
        files = open(self.currentPath + "/exploit-database/files_exploits.csv", encoding="utf-8")
        reader = csv.reader(files)
        next(reader)
        result = {'edbid':[], 'exploit':[], 'date':[], 'author':[], 'platform':[], 'type':[], 'port':[]}
        found = False
        for row in reader:
            edb, fileName, description, date, author, exploitType, platform, port = tuple(row)[:8]
            if edb in self.cveToExploitMap[cveSearch]:
                found = True
                result['edbid'].append(edb)
                result['exploit'].append(self.exploitDbPath + "/" + fileName)
                result['date'].append(date)
                result['author'].append(author)
                result['platform'].append(platform)
                result['type'].append(exploitType)
                
                if port != "0":
                    result['port'].append(port)
        if not found:
            if self.debug == True:
                print("ERROR - No EDB Id found")
        files.close()
        return result
    
    def openFile(self, exploitMap = "cveToEdbid.json", encoding="utf-8"):
        if not os.path.isdir(self.exploitDbPath):
            print("Cloning exploit-database repository")
            git.Repo.clone_from("https://gitlab.com/exploit-database/exploitdb.git", self.exploitDbPath)
            print("Updating db...")
            self.updateDb()
        else:
            if self.autoUpdate == True:
                print("Pulling exploit-database updates...")
                git.Git(self.exploitDbPath).pull('origin', 'main')
                print("Updating db...")
                self.updateDb()
            print("Loading database...")
            with open(self.currentPath + "/" + exploitMap, encoding="utf-8") as fileData:
                cveToExploitMap = json.load(fileData)
                self.cveToExploitMap = cveToExploitMap
                if self.debug == True:
                    print(self.cveToExploitMap)
    
    #create code   
    #init code
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
        
    def get_PoC(self):
        print('Get PoC Data in Github...')
        self.PoC_in_Github_path = "D:/02.Analyze_Vulnerabilities/vuln source/PoC-in-GitHub"
        self.trickest_cve_path = "D:\\02.Analyze_Vulnerabilities\\vuln source\\trickest-cve"
        self.PoC_in_Github_link = "https://github.com/nomi-sec/PoC-in-GitHub"
        self.trickest_cve_link = "https://github.com/trickest/cve"
        #self.PoC_in_Github_path = os.path.dirname(os.path.abspath(__file__)) + "/data/PoC-in-Github/"
        #self.trickest_cve_path = os.path.dirname(os.path.abspath(__file__)) + "/data/trickest-cve/"
        
        #clone PoC-in-Github
        if not os.path.isdir(self.PoC_in_Github_path):
            git.Repo.clone_from(self.PoC_in_Github_link+".git", self.PoC_in_Github_path)
        else :
            git.Git(self.PoC_in_Github_path).pull('origin', 'master')
        
        #clone trickest-cve
        if not os.path.isdir(self.trickest_cve_path):
            git.Repo.clone_from(self.trickest_cve_link+".git", self.trickest_cve_path)
        else :
            git.Git(self.trickest_cve_path).pull('origin', 'main')
        
        return
        
    #func        
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
        select_df = self.bp_df.copy()
        select_df = select_df[select_df['Reference'].str.contains('CVE|ExploitDb|www.exploit-db.com/exploits/', na=False)].reset_index(drop=False)
        select_df['Exploit'] = select_df['Reference'].apply(self.get_Exploit)
        #print(select_df[!isnan(select_df['Exploit'])])
        return select_df[['index', 'Exploit']]
        
    def get_Exploit(self, x): 
        exploit_nums = {}
        x_list = x.split(')')
        for xx in x_list:
            if "ExploitDb" in xx :
                Exploit_num = x.split('ExploitDb')[1].split()[0]
                exploit_nums[Exploit_num] = None
            
            elif "www.exploit-db.com/exploits/" in xx:
                Exploit_num = x.split('www.exploit-db.com/exploits/')[1].split('/')[0].split()[0]
                exploit_nums[Exploit_num] = None
                    
            elif "CVE" in xx:
                cve_num = 'CVE-'+ x.split('CVE')[1].split()[0]
                result = self.searchCve(cve_num)
                if len(result) != 0:
                    for Exploit_num in result['edbid']:
                        exploit_nums[Exploit_num] = None
                
        exploit_num = ""
        if len(exploit_nums) == 0:
            return np.NaN
        
        for num in exploit_nums.keys():
            exploit_num += f"www.exploit-db.com/exploits/{num}  "
        return exploit_num
        
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
                    result += temp+'\n----------------------------------\n'
        if len(result) == 0:
            return np.NaN
        return str(result)

    def merge_df(self, ex, net):
        merge_df = pd.merge(self.bp_df, ex, left_index=True, right_on='index', how='left').reset_index(drop=True).drop(columns='index')
        merge_df = pd.merge(merge_df, net, on='Network')
        self.bp_df = merge_df.copy()
        return

    def print_excel(self, path):
        excel_df = self.bp_df.copy()
        now = datetime.now()
        filename = f"result-{now.strftime('%Y-%m-%d_%H_%M_%S')}.xlsx"
        if path[-1] != '/' :
            path +='/'
        path += filename
        excel_df.to_excel(
            path,
            engine='xlsxwriter'
        )
        
    def save_db(self, user, passwd, address, dbname):
        mysql_conn_str = f'mysql+pymysql://{user}:{passwd}@{address}/{dbname}'
        db_connection = create_engine(mysql_conn_str)
        conn = db_connection.connect()
        dtypesql = {
            'Id':sqlalchemy.types.VARCHAR(16),
            'Name':sqlalchemy.types.VARCHAR(255),
            'Reference':sqlalchemy.types.TEXT,
            'Network':sqlalchemy.types.VARCHAR(255),
            'Exploit':sqlalchemy.dialects.mysql.MEDIUMTEXT,
            'Net_Exploit':sqlalchemy.dialects.mysql.MEDIUMTEXT,
            'CVSS':sqlalchemy.types.DECIMAL(3,1),
            'Priority':sqlalchemy.types.INT,
            'CVE':sqlalchemy.types.VARCHAR(40),
            'Github_PoC':sqlalchemy.dialects.mysql.MEDIUMTEXT
        }
        out_df = self.bp_df.copy()  
        out_df['Name'] = out_df['Name'].apply(lambda x: x.split('(')[0][:-1])
        out_df.to_sql(name='BP_CVE', con=db_connection, if_exists='replace', index=False, dtype=dtypesql)
        conn.execute(f"ALTER TABLE BP_CVE ADD PRIMARY KEY(Id);")
        conn.close()
        
        return
        
    def select_multiprocessing(self, n_cores=8):
        cvss_df = self.bp_df.copy()
        df_split = np.array_split(cvss_df, n_cores)
        pool = mp.Pool(n_cores)
        cvss_df = pd.concat(pool.map(self.apply_cvss, df_split))
        pool.close()
        pool.join()
        self.bp_df = cvss_df.copy()
        return
    
    def apply_cvss(self, df):
        df['CVSS'] = df.apply(lambda row: self.parse_cvss(row['Name']), axis=1)
        return df
    
    def parse_cvss(self, name):
        url = 'https://' + name.split('(https://')[1][:-1]
        page = requests.get(url)
        soup = bs(page.text, "lxml")
        cvss = soup.find('div', class_='field-name-field-cvss')
        if cvss != None:
            return float(cvss.text.split()[0])
        else : 
            return np.NaN
            
    def prioritize(self):
        priority_df = self.bp_df.copy()
        priority_df['Priority'] = priority_df.apply(lambda row: self.apply_priority(row),axis=1)
        priority_df['CVE'] = priority_df['Reference'].apply(lambda x: self.select_cve(x))
        priority_df = priority_df.sort_values(by=['Priority', 'CVE'], ascending=[True, False]).reset_index(drop=True)
        self.bp_df = priority_df.copy()
        return
    
    def apply_priority(self, x):
        ex = x['Exploit']
        net = x['Net_Exploit']
        cvss = x['CVSS']
        
        result = 4
        if ex != ex and net != net:
            result = 4
        elif (ex == ex and net != net) or (ex != ex and net == net):
            result = 3
        elif ex == ex and net == net and (cvss != cvss or cvss < 7):
            result = 2
        elif ex == ex and net == net and cvss == cvss and cvss > 7:
            result = 1
        return result
    
    def select_cve(self, x):
        if x == x and 'CVE' in x:
            return x.split('CVE')[1].split()[0]
        else :
            return np.NaN
        
    def count_priority(self):
        first = len(self.bp_df.loc[self.bp_df['Priority'] == 1])
        second = len(self.bp_df.loc[self.bp_df['Priority'] == 2])
        third = len(self.bp_df.loc[self.bp_df['Priority'] == 3])
        fourth = len(self.bp_df.loc[self.bp_df['Priority'] == 4])
        print(f'priority count: \n    first: {first}\n    second: {second}\n    third: {third}\n    fourth: {fourth}')
        
    def regive_ID(self, bp_num):
        temp_df = self.bp_df.copy()
        temp_df['Id'] = temp_df.apply(lambda row: f'M-BP-{bp_num}-{row["Priority"]}-{str(row.name+1).zfill(4)}', axis=1)
        temp_df = temp_df.drop(columns=['Time'])
        old_col = temp_df.columns[:-1].to_list()
        new_col = ['Id'] + old_col
        temp_df = temp_df[new_col]
        self.bp_df = temp_df.copy()
        
    def get_github_PoC(self):
        poc_df = self.bp_df.copy()
        
        poc_df['Github_PoC'] = poc_df['CVE'].apply(lambda x: self.apply_gitpoc(x) if x == x else np.NaN)
        self.bp_df = poc_df.copy()
        return
    
    def apply_gitpoc(self, x):
        year = x.split('-')[0]
        result = ""
        #PoC-in-Github
        if os.path.exists(self.PoC_in_Github_path+"/"+year+"/CVE-"+x+".json") :
                result += self.PoC_in_Github_link+'/blob/master/'+year+"/CVE-"+x+".json"
            
        #trickest-cve
        if os.path.exists(self.trickest_cve_path+"/"+year+"/CVE-"+x+".md") :
                result += " "
                result += self.trickest_cve_link+'/blob/main/'+year+"/CVE-"+x+".md"
        
        if len(result) != 0:
            return result
        return np.NaN
    
    def get_db(self, user, passwd, address, dbname, tablename):
        db_df = pd.read_sql_table(tablename, f'mysql+pymysql://{user}:{passwd}@{address}/{dbname}')
        return db_df
    
    def compare_df(self, db_df):
        # compare Github_PoC
        temp_bp_df = self.bp_df.copy()
        if not db_df[['Github_PoC']].equals(temp_bp_df[['Github_PoC']]):
            git_db_s = db_df['Github_PoC'].fillna("")
            git_bp_s = self.bp_df['Github_PoC'].fillna("")
            git_eq_s = ~git_bp_s.eq(git_db_s, fill_value=0)
            db_eq_df = db_df[git_eq_s].loc[:,['Id', 'Github_PoC']]
            bp_eq_df = temp_bp_df[git_eq_s].loc[:,['Id', 'Github_PoC']]
            compare_df = pd.merge(db_eq_df, bp_eq_df, how="outer", on='Id')
            compare_df = compare_df.rename(columns={'Github_PoC_x':'Before', 'Github_PoC_y':'After'})
            print(compare_df)
        else :
            print('Not Add Github_PoC')
        return
    
    
def sample():
    bp_cve = BP_CVE()
    bp_cve.read_Excel('data/TA-BP-CVE-TEST.xlsx', 'arrange-jk')
    
    print('select exploit..')
    ex_df = bp_cve.select_exploitdb()
    net_df = bp_cve.select_pcap()
    print('merge dataframe..')
    bp_cve.merge_df(ex_df, net_df)
    print('get CVSS...')
    bp_cve.select_multiprocessing()
    print('prioritize...')
    bp_cve.prioritize()
    print('regive ID...')
    bp_cve.regive_ID('2204')
    print('get PoC in Github...')
    bp_cve.get_github_PoC()
    
    print('Compare DB and bp_df...')
    db_df = bp_cve.get_db('bp', '4523','10.0.0.206:3306','bp_cve', 'BP_CVE')
    bp_cve.compare_df(db_df)
    
    print('make excel...')
    bp_cve.print_excel('data/')
    print('write DB...')
    bp_cve.save_db('bp', '4523','10.0.0.206:3306','bp_cve')
    bp_cve.count_priority()
    
    
def main():
    parser = argparse.ArgumentParser(description='BP-CVE Data Collection Automation Tool')
    parser.add_argument('-f', dest='bpcveexcel',help='read BP-CVE xlsx file path', required=True)
    parser.add_argument('--sheet', dest='bpcveexcelsheet',help='read BP-CVE xlsx file sheet name',required=True)
    parser.add_argument('-o', '--output', dest='output', help='outfile directory path (defalut data/)', default='data/', required=False)
    parser.add_argument('--bp-num',  dest='bpnum', help='bp version(date)', required=True)
    parser.add_argument('--db-user', dest='dbuser', help='MySQL DataBase User name', required=True)
    parser.add_argument('--db-passwd', dest='dbpasswd', help='MySQL DataBase Password', required=True)
    parser.add_argument('--db-host', dest='dbhost', help='MySQL DataBase Host(:port)', required=True)
    parser.add_argument('--db', dest='db', help='MySQL DataBase', required=True)
    
    args = parser.parse_args()
    #print(args)
    
    bp_cve = BP_CVE()
    bp_cve.read_Excel(args.bpcveexcel, args.bpcveexcelsheet)
    
    print('select exploit..')
    ex_df = bp_cve.select_exploitdb()
    net_df = bp_cve.select_pcap()
    print('merge dataframe..')
    bp_cve.merge_df(ex_df, net_df)
    print('get CVSS...')
    bp_cve.select_multiprocessing()
    print('prioritize...')
    bp_cve.prioritize()
    print('regive ID...')
    bp_cve.regive_ID(args.bpnum)
    print('Compare DB and bp_df...')
    db_df = bp_cve.get_db(args.dbuser, args.dbpasswd, args.dbhost, args.db, 'BP_CVE')
    bp_cve.compare_df(db_df)
    
    print('make excel...')
    bp_cve.print_excel(args.output)
    print('write DB...')
    bp_cve.save_db(args.dbuser, args.dbpasswd, args.dbhost, args.db)
    
    return

if __name__ == "__main__":
    sample()
    #main()