from pyExploitDb import PyExploitDb
from scapy.all import *
import json

def test_pyexploitdb():
    pEdb = PyExploitDb()
    pEdb.debug = False
    pEdb.openFile()
    
    results = pEdb.searchCve("CVE-2019-11539")
    if len(results) != 0:
        with open(results['exploit'], 'r', encoding='UTF8') as f:
            print(f.read())

def test_scapy():
    load_layer("http")
    pkts = sniff(offline="./data/tcpdump/S1E1.pcap", session=TCPSession)
    print(pkts.show())


def main():
    test_pyexploitdb()
    return

if __name__ == "__main__":
    main()