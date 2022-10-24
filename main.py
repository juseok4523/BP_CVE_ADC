from csv import excel
from multiprocessing import set_forkserver_preload
import numpy as np
import pandas as pd


class BP_CVE:
    def __init__(self):
        self.bp_df = None
        
        
        
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
        excel_df = excel_df.rename(columns={'Time of strike':'time', 'Strike Name':'name', 'Strike Reference':'reference', 'Strike Tuples':'network'})
        
        self.bp_df = excel_df.sort_values('time').reset_index(drop=True)
        print(self.bp_df) #debug
        return


def main():
    bp_cve = BP_CVE()
    #test
    bp_cve.read_Excel('data/TA-BP-CVE-TEST-attack_report-2022.07-arrange-jk.xlsx', 'arrange-jk')
    
    #product
    return

if __name__ == "__main__":
    main()