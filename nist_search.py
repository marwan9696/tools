#Tool to search with a keyword in NVD (NATIONAL VULNERABILITY DATABASE) and look for CVEs
import argparse
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import re

# Current date
now = datetime.now()
today = now.strftime("%Y-%m-%d-%H_%M_%S")

#csv columns
csv = "cve,cvss,CWE,description,CPE_affected_devices,Reference\n"

#convert list to csv
def export_to_csv():
    print("\nGenerated CSV: ./" + today + "-resultNVD.csv\n")
    f = open(today + "-resultNVD.csv", "a",encoding='UTF8')
    f.write(csv)
    f.close()

#search for CVE, CVSS,CWE,Description, CPE, reference
def searchcve(url):
    cves_list = []
    global csv

    base_request = requests.get(url)
    if base_request.status_code == 200:
        base_text = base_request.text
        cve_search = re.findall("CVE-[0-9]{4}-[0-9]{4,}", base_text)
        if cve_search == []:
            print("No CVE found")
            return

        # Get CVEs
        cves_list = sorted(set(cve_search))

        for i in range (0, len(cves_list)):

            nist_url = "https://nvd.nist.gov/vuln/detail/" + cves_list[i]
            nist_request = requests.get(nist_url) 

            soup = BeautifulSoup( nist_request.text, "html.parser" )

            #get CVSS
            try: 
                parent = soup.find( "input",attrs={ "id" : "nistV3MetricHidden" } )["value"]
                soup_internal = BeautifulSoup(parent, "html.parser" )
                cvss = soup_internal.find_all( 
                    "span", 
                    attrs={ 
                        "data-testid": "vuln-cvssv3-base-score" 
                    } 
                )[0].string.strip()
            except Exception: 
                cvss = "Unknown" 
            
            #get Description
            try: 
                description = soup.find_all("p", attrs={ "data-testid": "vuln-description" })[0].string.strip().replace(',',' ')
            except Exception:
                description = "Unknown"
            #get CWE
            try:
                CWE = soup.find_all("a",text=re.compile('CWE-'))[0].string.strip().replace(',',' ')            
            except Exception:
                CWE = "Unknown"
        
            #get Reference
            try:
                Reference = soup.find_all("pre",text=re.compile('http'))[0].string.strip().replace(',',' ').replace('No Types Assigned','')
            except Exception:
                Reference = "Unknown"
            
            #get CPE
            try:
                CPE = soup.find_all("pre",text=re.compile('cpe:'))[0].string.replace(',',' ').replace('OR',' ').replace('AND',' ').replace('*','').replace('\n','   ').strip()
            except Exception:
                CPE = "Unknown"

            #add to csv variable
            csv += cves_list[i] + "," + cvss + "," + CWE + "," + description+ "," +CPE+","+ Reference +"\n"
            
        #Export to csv
        export_to_csv()
        csv = ""

    else:
        raise Exception( "HTTP error: " + str(base_request.status_code) ) 

def main(): 
    parser = argparse.ArgumentParser()
    parser.add_argument('-k','--keyword', help='Choose keyword to look for in NVD')
    global args
    args = parser.parse_args()

    if args.keyword:
        searchcve("https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=" + args.keyword)

if __name__ == "__main__":
        main()
