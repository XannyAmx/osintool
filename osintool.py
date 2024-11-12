import dns.resolver, whois, signal, sys, argparse, os, time, requests, json
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from waybackpy import WaybackMachineCDXServerAPI

def getArguments():
    parse = argparse.ArgumentParser(description="OSINT tool on domain and subdomains")
    parse.add_argument('-o', '--osint', dest="osint", help="Wayback utility", action="store_true")
    parse.add_argument('-g', '--google', dest="google", help="Utility of google dork", action="store_true")
    parse.add_argument('-c', '--cx', dest="cx", help="Programmable search engine")
    parse.add_argument('-k', '--key', dest="key", help="Google API key") 
    parse.add_argument('-f', '--file', dest="file", help="Type of file to search")
    parse.add_argument('-d', '--domain', dest="domain", help="Main domain")
    parse.add_argument('-w', '--wordlist', dest="wordlist", help="Wordlist of subdomains")
    parse.add_argument('-t', '--time', dest="time", help="Time of collection delay")
    args = parse.parse_args()

    if args.osint and args.domain and args.wordlist and args.time:
        return args
    elif args.google and args.cx and args.key and args.domain and args.file:
        return args
    else:
        parse.print_help()
        sys.exit(1)

def ctrl_c(fram, val):
    print(colored(f"\n\n[!] Exit...", "red"))
    sys.exit(1)
signal.signal(signal.SIGINT, ctrl_c)

class Osintool():

    def __init__(self, principalDomain, wordlist="", time="", cx="", key="", file=""):
        self.principalDomain = principalDomain
        self.wordlistSubdomain = (self.load_file(wordlist) if wordlist else None)
        self.timeAgo = time
        self.cx = cx
        self.key = key
        self.file = file

        self.subdomains = []
        self.subdomains.append(principalDomain)
        self.recordTypes = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        self.ipServersDomain = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "84.200.69.80", "84.200.70.40"]
        self.resolverDNS = self.setup_resolver(2.5)
        self.userAgent = "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0"
        self.extensions = ["pdf","doc","docx","ppt","xls","xlsx","txt","jpg","png","jpeg", "sql","log"]
        self.importantData = ["pdf","doc","docx","ppt","xls","xlsx", "sql","log"]
        self.filesDownloadsTotal = 0
        self.nameFileImportant = []
        self.filesURL = []
        self.filesTotal = 0

    def load_file(self, path):
        try:
            with open(path, 'r', encoding="latin-1") as file:
                return file.read().splitlines()
        except FileNotFoundError:
            print(colored(f"\t[!] Error: The file could not be opened: {path}","red"))
            sys.exit(1)

    def setup_resolver(self, timeOutDNS):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeOutDNS
        resolver.lifetime = timeOutDNS
        resolver.nameservers = self.ipServersDomain
        return resolver

    def scanSubdomains(self):
        with ThreadPoolExecutor(max_workers=500) as executor:
            results = list(executor.map(self._scan_domain, self.wordlistSubdomain))
        self._present_results(results)

    def dnsEnumeration(self, domain):
        resolver = dns.resolver.Resolver()
        self.addSummary(f"[+] DNS records of the domain: {domain}", domain)
        for recordType in self.recordTypes:
            try:
                answers = resolver.resolve(domain, recordType)
            except:
                continue
            self.addSummary(f"\n\tRecord '{recordType}' of the {domain}:", domain)
            for data in answers:
                self.addSummary(f"\n\t\t{data}", domain)

    def whoisEnumeration(self, domain):
        response = whois.whois(domain)
        if response:
            self.addSummary(f"\n\n[+] WHOIS record of the domain {domain}:\n{response}", domain)

    def snapshotDomain(self, domain):
        time.sleep(10)

        targetDate = datetime.now() - timedelta(days=365 * int(self.timeAgo))
        year, month, day = targetDate.year, targetDate.month, targetDate.day

        time.sleep(5)

        try:
            cdxApi = WaybackMachineCDXServerAPI(domain, self.userAgent)
            snapshot = cdxApi.near(year=year, month=month, day=day)

            try:
                if snapshot:
                    download = requests.get(snapshot.archive_url)
                    with open(f"./{self.principalDomain}/Snapshot_{domain}.html", "w") as f:
                        f.write(download.text)
                    self.addSummary(f"\n\n[+] Snapshot of the domain {domain}\n\t{snapshot.archive_url}", domain)
                    print(colored(f"[+] Snapshot of the {domain} domain completed (./{self.principalDomain}/Snapshot_{domain}.html)", "green"))
            except Exception as e:
                print(colored(f"\t[!] Snapshot error: {e}","red"))
        except:
            pass

    def contentDomain(self, domain):
        today = datetime.now()
        startPeriod = (today - timedelta(days=365 * int(self.timeAgo))).strftime('%Y%m%d')
        endPeriod = datetime.now().strftime('%Y%m%d')

        try:
            cdxApi = WaybackMachineCDXServerAPI(domain, self.userAgent, start_timestamp=startPeriod,end_timestamp=endPeriod, match_type="domain")
            regexFilter = "(" + "|".join([f".*\\.{ext}$" for ext in self.extensions]) + ")"
            cdxApi.filters = [f"urlkey:{regexFilter}"]
            snapshot = cdxApi.snapshots()

            self.addSummary(f"\n\n[+] Files found:", domain)
            for snap in snapshot:
                self.addSummary(f"\n{snap.archive_url}", domain)
                extensionFile = str(snap.archive_url).split(".")[-1]
                self.filesTotal += 1

                if extensionFile in self.importantData:
                    self.filesDownloadsTotal += 1
                    self.nameFileImportant.append(snap.archive_url)
                    filename = f"{snap.archive_url.split('/')[-1]}"

            self.addSummary(f"\n\n[+] Total files found: {self.filesTotal}", domain)
            self.addSummary(f"\n\n[+] Relevant files found: {self.filesDownloadsTotal}", domain)
            for nameFile in self.nameFileImportant:
                self.addSummary(f"\n{nameFile}", domain)
                self.filesURL.append(nameFile)

            self.filesTotal, self.filesDownloadsTotal = 0,0
            self.nameFileImportant = []

        except Exception as e:
            print(colored(f"\t[!] Error in API Wayback Machine: {e}","red"))

        print(colored(f"[+] Summary of the {domain} domain completed (./{self.principalDomain}/Summary_{domain}.txt)", "green"))

    def _scan_domain(self, subdomain):
        full_domain = f"{subdomain}.{self.principalDomain}"
        try:
            answers = self.resolverDNS.resolve(full_domain, "A")
            return (full_domain, [answer.address for answer in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return None
        
    def _present_results(self, results):
        if not results or all(result is None for result in results):
            pass
        else:
            self.addSummary(f"[+] Subdomains found:", self.principalDomain)
            for result in results:
                if result:
                    domain, addresses = result
                    self.subdomains.append(domain)
                    self.addSummary(f"\n\t{domain}", self.principalDomain)
                    for add in addresses:
                        self.addSummary(f"\n\t\t{add}", self.principalDomain)
            self.addSummary(f"\n\n",self.principalDomain)
    
    def downloadFiles(self):
        if not os.path.exists(F"./{self.principalDomain}"):
            os.mkdir(f"./{self.principalDomain}")
        question = input(colored(f"\n[?] Do you want to download the relevant documents found? (Y/N): ", "magenta"))
        if question == "Y" or question == "y":
            i = 0
            for file in self.filesURL:
                dl = input(colored(f"\n\t>> Download {file}? (Y/N): ", "magenta"))
                if dl == "Y" or dl == "y":
                    try:
                        download = requests.get(file)
                        filePath = file.split('/')[-1]
                        i += 1
                        with open(f"./{self.principalDomain}/File{i}_{filePath}", "wb") as f:
                            f.write(download.content)
                        print(colored(f"\t[+] Successful download (./{self.principalDomain}/File{i}_{filePath})", "green"))
                    except Exception as e:
                        print(colored(f"\t[!] Download error: {e}", "red"))

    def addSummary(self, text, domain):
        with open(f"./{self.principalDomain}/Summary_{domain}.txt", "a") as f:
            f.write(text)

    def waybakcmachine(self):
        if not os.path.exists(F"./{self.principalDomain}"):
            os.mkdir(f"./{self.principalDomain}")
        self.scanSubdomains()
        for domain in self.subdomains:
            self.dnsEnumeration(domain)
            self.whoisEnumeration(domain)
            self.snapshotDomain(domain)
            self.contentDomain(domain)
        self.downloadFiles()

    def googleDork(self):
        try:
            query = f"site:{self.principalDomain} filetype:{self.file}"
            url = f"https://www.googleapis.com/customsearch/v1?key={self.key}&cx={self.cx}&q={query}"
            res = requests.get(url).json()
            items = res.get("items")
            i = 0
            for item in items:
                i +=1
                print(colored(f"\n\t[+] Result {i}: ", "green"))
                print(f'\t{item.get("title")}')
                print(f'\t{item.get("snippet")}')
                print(f'\t{item.get("link")}')
                self.filesURL.append(item.get("link"))
                time.sleep(.2)
            self.downloadFiles()
        except Exception as e:
            print(colored(f"[!] Error in Google API or no result: {e}","red"))
        finally:
            return colored(f"\n[+] Google search completed\n", "green")

def parseDomain(domainsArg):
    if ',' in domainsArg:
        domains = domainsArg.split(",")
        return domains
    else:
        domains = [domainsArg]
        return domains

def banner():
    print(colored("""
   ____      _____    _____      __      _   ________     ____       ____     _____
  / __ \    / ____\  (_   _)    /  \    / ) (___  ___)   / __ \     / __ \   (_   _)
 / /  \ \  ( (___      | |     / /\ \  / /      ) )     / /  \ \   / /  \ \    | |
( ()  () )  \___ \     | |     ) ) ) ) ) )     ( (     ( ()  () ) ( ()  () )   | |
( ()  () )      ) )    | |    ( ( ( ( ( (       ) )    ( ()  () ) ( ()  () )   | |   __
 \ \__/ /   ___/ /    _| |__  / /  \ \/ /      ( (      \ \__/ /   \ \__/ /  __| |___) )
  \____/   /____/    /_____( (_/    \__/       /__\      \____/     \____/   \________/

Author: Xanny A (Daniel Martìnez)""", "red"))

def main():
    banner()
    args = getArguments()

    if args.osint:
        print(colored(f"\n[>] Wayback Machine search\n", "magenta"))
        domains = parseDomain(args.domain)
        for domain in domains:
            domain = Osintool(str(domain).strip(), wordlist=args.wordlist, time=args.time)
            domain.waybakcmachine()
    if args.google:
        print(colored(f"\n[>] Google Search", "magenta"))
        domains = parseDomain(args.domain)
        for domain in domains:
            domain = Osintool(str(domain).strip(), cx=args.cx, key=args.key, file=args.file)
            domain.googleDork()
    print(colored(f"\n[>] Happy OSINT  ;)","red"))

if __name__ == "__main__":
    main()