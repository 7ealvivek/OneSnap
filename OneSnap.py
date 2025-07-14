#!/usr/bin/env python3

import sys
import subprocess
import os
import importlib.util

# Self-contained dependency checker
def check_and_install_dependencies():
    required_packages = {'requests': 'requests', 'tqdm': 'tqdm', 'tldextract': 'tldextract', 'shodan': 'shodan'}
    missing = [p for p, i in required_packages.items() if importlib.util.find_spec(i) is None]
    if missing:
        print(f"[!] Missing packages: {', '.join(missing)}. Installing...")
        for package in missing:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"[✓] Successfully installed '{package}'.")
            except subprocess.CalledProcessError:
                print(f"[✗] ERROR: Failed to install '{package}'. Please install it manually."); sys.exit(1)
        print("\n[*] Relaunching script..."); os.execv(sys.executable, ['python'] + sys.argv)

check_and_install_dependencies()

import argparse
import zipfile
import json
import shutil
import time
import concurrent.futures
from pathlib import Path
from tqdm import tqdm
import requests
import tldextract
import shodan
import re

# ASCII Art
ASCII_BANNER = r"""
 ___````````````````````______```````````````````````````
`.'````.````````````````.'`____`\``````````````````````````
/``.-.``\`_`.--.``.---.`|`(___`\_|_`.--.```,--.``_`.--.```
|`|```|`|[``.-.`|/`/__\\`_.____`.`[``.-.`|``'_\`:[`'/'`\`\`
\```-'``/`|`|`|`|`||`\__.,|`\____)`|`|`|`|`|`//`|`|,|`\__/|`
``.___.'`[___||__]'.__.'`\______.'[___||__]\'-;__/|`;.__/``
`````````````````````````````````````````````````[__|``````
"""

# --- Configuration ---
SCRIPT_NAME = "One Snap: The Universal Bounty Subdomain Harvester"
AUTHOR = "x.com/starkcharry | github.com/7ealvivek | bugcrowd.com/realvivek"
C99_API_KEY = "YOUR-API-KEY"
SHODAN_API_KEY = "YOUR-API-KEY"
C99_DOMAIN_DELAY = 10
SHODAN_API_DELAY = 1
ZIP_DIR = "chaos_zips"
EXTRACT_DIR = "extracted"
CHAOS_INDEX = "https://chaos-data.projectdiscovery.io/index.json"

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

class OneSnapGUI:
    def __init__(self, master):
        master.title("One Snap GUI"); master.geometry("500x600"); master.resizable(False, False)
        master.tk_setPalette(background='#ececec', foreground='#333333', activeBackground='#c0c0c0', activeForeground='#000000')
        font_label=('Arial', 10);font_button=('Arial',10,'bold');font_header=('Arial',12,'bold')
        tk.Label(master,text=SCRIPT_NAME,font=font_header,fg='darkblue').pack(pady=(15,5))
        tk.Label(master,text=AUTHOR,font=('Arial',8,'italic')).pack(pady=(0,10))
        tk.Label(master,text="Specific Program(s) (optional, space-separated):",font=font_label,anchor="w").pack(fill="x",padx=20,pady=(10,0))
        self.program_entry=tk.Entry(master,font=font_label)
        self.program_entry.pack(fill="x",padx=20,pady=(0,10))
        tk.Label(master,text="Private Subdomains List:",font=font_label,anchor="w").pack(fill="x",padx=20,pady=(5,0))
        self.private_file_path=tk.StringVar();self.private_file_path.set("No private list selected.")
        tk.Label(master,textvariable=self.private_file_path,font=font_label,fg='gray').pack(fill="x",padx=20)
        tk.Button(master,text="Select Private List",command=self.ask_private,font=font_button).pack(pady=(5,15))
        tk.Frame(master,height=1,bg="lightgray").pack(fill="x",padx=15,pady=5)
        tk.Label(master,text="Data Sources & Processing:",font=font_label,anchor="w").pack(fill="x",padx=20,pady=(10,0))
        self.shodan_var=tk.BooleanVar();tk.Checkbutton(master,text="Use Shodan (Comprehensive & Safe)",variable=self.shodan_var,font=font_label).pack(anchor="w",padx=20)
        self.httpx_var=tk.BooleanVar();tk.Checkbutton(master,text="Run httpx with chunking",variable=self.httpx_var,font=font_label).pack(anchor="w",padx=20)
        self.rerun_chaos_var=tk.BooleanVar();tk.Checkbutton(master,text="Force full Chaos data download",variable=self.rerun_chaos_var,font=font_label).pack(anchor="w",padx=20)
        tk.Frame(master,height=1,bg="lightgray").pack(fill="x",padx=15,pady=15)
        tk.Label(master,text="Filter Chaos Data by Bounty Platform:",font=font_label,anchor="w").pack(fill="x",padx=20,pady=(0,5))
        self.platform_vars={"bugcrowd":tk.BooleanVar(),"hackerone":tk.BooleanVar(),"intigriti":tk.BooleanVar(),"yeswehack":tk.BooleanVar(),"hackenproof":tk.BooleanVar()}
        pf=tk.Frame(master);pf.pack(anchor="w",padx=20,pady=5)
        for i,(p,v) in enumerate(self.platform_vars.items()):tk.Checkbutton(pf,text=p.title(),variable=v,font=font_label).grid(row=i//2,column=i%2,sticky="w")
        tk.Frame(master,height=1,bg="lightgray").pack(fill="x",padx=15,pady=15)
        self.run_button=tk.Button(master,text="Run One Snap",command=self.run_script,font=('Arial',12,'bold'),bg='darkgreen',fg='white')
        self.run_button.pack(pady=10,ipadx=20,ipady=5);self.private_file=None
    def ask_private(self):
        fn=filedialog.askopenfilename(title="Select Private Subdomains List",filetypes=[("Text files","*.txt")])
        if fn:self.private_file=fn;self.private_file_path.set(f"Private list: {os.path.basename(fn)}")
    def run_script(self):
        self.run_button.config(state=tk.DISABLED,text="Running...");self.master.update_idletasks()
        try:
            programs=self.program_entry.get().split()
            platforms=[n for n,v in self.platform_vars.items() if v.get()]
            run_one_snap(program_names=programs,private_txt=self.private_file,rerun_chaos=self.rerun_chaos_var.get(),run_httpx=self.httpx_var.get(),run_shodan=self.shodan_var.get(),selected_bounty_platforms=platforms)
            messagebox.showinfo("Success","One Snap: Done!")
        except Exception as e:messagebox.showerror("Unexpected Error",f"An unexpected error occurred: {e}")
        finally:self.run_button.config(state=tk.NORMAL,text="Run One Snap",bg='darkgreen',fg='white')

# --- Utility Functions ---

def fetch_chaos_index():
    try:
        print(f"[*] Fetching Chaos index from: {CHAOS_INDEX}")
        r=requests.get(CHAOS_INDEX,timeout=15);r.raise_for_status();return r.json()
    except(requests.RequestException,json.JSONDecodeError)as e:
        print(f"[!] Error with Chaos index: {e}.");return None

def download_chaos(chaos_index_data,program_names=None,selected_platforms=None,rerun_chaos=False):
    Path(ZIP_DIR).mkdir(exist_ok=True);Path(EXTRACT_DIR).mkdir(exist_ok=True)
    if not chaos_index_data:return
    urls=[]
    if rerun_chaos:
        print("[*] --rerun-chaos flag is set. Downloading all Chaos data.")
        urls=[i["URL"] for i in chaos_index_data]
    elif program_names:
        print(f"[*] Filtering Chaos for program(s): {', '.join(program_names)}")
        program_set={p.lower() for p in program_names}
        for item in chaos_index_data:
            if any(p in item.get("name","").lower()for p in program_set):urls.append(item["URL"])
    elif selected_platforms:
        print(f"[*] Filtering Chaos for platform(s): {', '.join(selected_platforms)}")
        platform_set={p.lower() for p in selected_platforms};urls=[i["URL"] for i in chaos_index_data if i.get("platform","").lower()in platform_set]
    if not urls:
        if program_names or selected_platforms:print("[!] No matching programs or platforms found in Chaos index.")
        return
    print(f"[*] Identified {len(urls)} Chaos ZIPs for processing.")
    session=requests.Session()
    session.mount('https://',requests.adapters.HTTPAdapter(max_retries=requests.packages.urllib3.util.retry.Retry(total=5,backoff_factor=1)))
    for url in tqdm(urls,desc="[↓] Downloading & Extracting Chaos Zips"):
        zip_path=Path(ZIP_DIR)/os.path.basename(url)
        if not zip_path.exists():
            try:
                with session.get(url,stream=True,timeout=30)as r:r.raise_for_status();open(zip_path,'wb').write(r.content)
            except requests.RequestException as e:print(f"\n[!] Failed to download {url}: {e}");continue
        try:
            with zipfile.ZipFile(zip_path,'r')as zf:zf.extractall(EXTRACT_DIR)
        except(zipfile.BadZipFile,Exception)as e:print(f"\n[!] Error extracting {zip_path}: {e}")

def extract_chaos_subdomains():
    subs=set()
    for file in Path(EXTRACT_DIR).rglob("*.txt"):
        with open(file,'r',encoding='utf-8',errors='ignore')as f:
            subs.update(line.strip().lstrip("*.")for line in f if line.strip())
    return subs

def get_root_domains(subdomains):
    return sorted({tldextract.extract(s.strip()).registered_domain for s in subdomains if s.strip()and tldextract.extract(s.strip()).registered_domain})

def query_c99(domains):
    result = set(); failed_domains = []
    if not domains: return result
    if not C99_API_KEY or C99_API_KEY == "[YOUR_C99_API_KEY_HERE]":
        print("[!] C99_API_KEY not configured. Skipping C99 queries."); return result
    
    def fetch_from_api(url):
        try:
            res = requests.get(url, timeout=300).json()
            if res.get("success") is True:
                return {s.get("subdomain", "").strip() for s in res.get("subdomains", []) if s.get("subdomain")}, res.get("next_page")
            elif "rate limit" in res.get("error", "").lower(): return "RATE_LIMIT", None
        except (requests.RequestException, json.JSONDecodeError): pass
        return None, None

    print(f"[*] Starting C99 scan for {len(domains)} root domains...")
    for domain in tqdm(domains, desc="[C99] Querying domains"):
        next_page_url = f"https://api.c99.nl/subdomainfinder?key={C99_API_KEY}&domain={domain}&realtime=true"
        domain_subs, domain_failed_permanently = set(), False
        
        while next_page_url:
            subs, next_page = fetch_from_api(next_page_url)
            if subs is None: failed_domains.append(domain); domain_failed_permanently = True; break
            if subs == "RATE_LIMIT":
                tqdm.write(f"\n[!] C99 Rate Limit on {domain}. Pausing for 60s and retrying..."); time.sleep(60)
                subs, next_page = fetch_from_api(next_page_url)
                if subs is None or subs == "RATE_LIMIT": failed_domains.append(domain); domain_failed_permanently = True; break
            
            domain_subs.update(subs); next_page_url = next_page
        
        if not domain_failed_permanently: result.update(domain_subs)
        time.sleep(C99_DOMAIN_DELAY)

    if failed_domains:
        print(f"\n[!] The following {len(set(failed_domains))} domain(s) failed to return complete data from C99:")
        for d in sorted(list(set(failed_domains))): print(f"    - {d}")
            
    return result

def query_shodan_comprehensively(domains):
    if not domains:return set()
    if not SHODAN_API_KEY or SHODAN_API_KEY=="[YOUR_SHODAN_API_KEY_HERE]":
        print("\n[!] Shodan API key is not configured in the script. Skipping Shodan scan.")
        return set()
    try:api=shodan.Shodan(SHODAN_API_KEY);api.info()
    except shodan.APIError as e:print(f"\n[!] Shodan API Error: {e}. Please check the key.");return set()
    
    all_found_subs=set()
    valid_hostname_re=re.compile(r"^[a-zA-Z0-9.-]+$")
    def clean_and_validate(sub,domain):
        cleaned=re.sub(r'[\x00-\x1f\x7f-\x9f* ]','',sub).strip('.').lower()
        if cleaned.endswith(f".{domain}")and valid_hostname_re.match(cleaned):return cleaned
        return None

    total_queries = len(domains) * 3
    print(f"[*] Starting comprehensive Shodan scan for {len(domains)} root domains ({total_queries} total API queries)...")

    with tqdm(total=total_queries, desc="[Shodan] Executing Queries") as pbar:
        for domain in domains:
            queries = [f"hostname:{domain}", f"ssl.cert.subject.CN:{domain}", f"ssl.cert.subject.alt_name:{domain}"]
            for query in queries:
                try:
                    results = api.search(query)
                    for match in results.get("matches", []):
                        if hostnames := match.get("hostnames", []):
                            for h in hostnames:
                                if isinstance(h, str):
                                    if cleaned := clean_and_validate(h, domain): all_found_subs.add(cleaned)
                        if ssl := match.get("ssl", {}):
                            if cert := ssl.get("cert", {}):
                                if subject := cert.get("subject", {}):
                                    if cn := subject.get("CN", ""):
                                        if isinstance(cn, str):
                                            if cleaned := clean_and_validate(cn, domain): all_found_subs.add(cleaned)
                                if exts := cert.get("extensions", []):
                                    for ext in exts:
                                        if ext.get("name") == "subjectAltName":
                                            for san in ext.get("data", "").split(","):
                                                if isinstance(san, str):
                                                    if cleaned := clean_and_validate(san, domain): all_found_subs.add(cleaned)
                except shodan.APIError as e:
                    pbar.write(f"\n[!] Shodan API error on query '{query}': {e}. Continuing...")
                
                pbar.update(1)
                time.sleep(SHODAN_API_DELAY)
                
    return all_found_subs

def save_final_output(subdomains,txt_file,zip_file):
    unique_subs=sorted(list(subdomains))
    print(f"\n[*] Saving {len(unique_subs)} unique subdomains to {txt_file} and zipping...")
    try:
        with open(txt_file,'w')as f:f.write('\n'.join(unique_subs))
        with zipfile.ZipFile(zip_file,'w',zipfile.ZIP_DEFLATED)as zf:zf.write(txt_file,os.path.basename(txt_file))
        print(f"[✓] Final list saved: {txt_file} and {zip_file}")
    except Exception as e:print(f"[!] Error saving final output: {e}")

def run_httpx_scan_with_shell(input_file,output_file):
    if not all(shutil.which(cmd)for cmd in["httpx","split"]):
        print("[!] `httpx` or `split` command not found. Please ensure both are in your PATH.");return
    if not Path(input_file).exists()or Path(input_file).stat().st_size==0:
        print(f"[!] httpx input file '{input_file}' empty or not found. Skipping.");return
    total_lines=sum(1 for _ in open(input_file))
    print(f"[*] Initiating your chunk-based httpx scan for {total_lines} subdomains...")
    temp_dir=Path("./httpx_chunks_temp")
    try:
        if temp_dir.exists():shutil.rmtree(temp_dir)
        temp_dir.mkdir()
        subprocess.run(["split","-l","50000",input_file,str(temp_dir/"chunk_")],check=True)
        chunk_files=sorted(list(temp_dir.glob("chunk_*")))
        if not chunk_files:print("[!] No chunk files created. Aborting httpx.");return
        print(f"[*] Input split into {len(chunk_files)} chunks. Running your command in parallel...")
        if Path(output_file).exists():open(output_file,'w').close()
        full_command=f'for file in {temp_dir}/chunk_*; do cat "$file" | httpx -threads 100 -timeout 5 -mc 200,301,302,404,405,401 -silent >> "{os.path.abspath(output_file)}" & done; wait'
        start_time=time.time()
        process=subprocess.Popen(full_command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process.communicate()
        if process.returncode!=0:print("[!] An error occurred during the httpx shell command execution.")
        else:print(f"[✓] HTTPX scan completed in {time.strftime('%Hh %Mm %Ss',time.gmtime(time.time()-start_time))}. Results in: {output_file}")
    except(subprocess.CalledProcessError,Exception)as e:
        print(f"[!] An error occurred during the httpx scan: {e}")
    finally:
        if temp_dir.exists():
            print("[*] Cleaning up httpx temporary chunk files...");shutil.rmtree(temp_dir);print("[✓] httpx cleanup complete.")

# --- Main Logic ---

def run_one_snap(program_names=None,private_txt=None,rerun_chaos=False,run_httpx=False,run_shodan=False,selected_bounty_platforms=None):
    has_public_scope=program_names or selected_bounty_platforms or rerun_chaos
    if program_names:base="_".join(sorted(p.lower()for p in program_names))
    elif selected_bounty_platforms:base="_".join(sorted(selected_bounty_platforms))
    elif private_txt:base=f"private_{Path(private_txt).stem}"
    else:base="all_chaos"
    final_txt=f"{base}_subs.txt";final_zip=f"{base}_subs.zip";final_httpx=f"live_{base}_subs.txt"
    all_subs,root_domains=set(),set()
    if has_public_scope:
        chaos_index=fetch_chaos_index()
        download_chaos(chaos_index,program_names=program_names,selected_platforms=selected_bounty_platforms,rerun_chaos=rerun_chaos)
        chaos_subs=extract_chaos_subdomains();all_subs.update(chaos_subs)
    else:
        print("[*] No public data source selected. Processing private list only.")
    if private_txt:
        try:
            with open(private_txt,'r')as f:priv_subs={line.strip()for line in f if line.strip()}
            print(f"[*] Loaded {len(priv_subs)} domains from private list: {private_txt}")
            all_subs.update(priv_subs)
        except FileNotFoundError:print(f"[!] Private file not found: {private_txt}");sys.exit(1)
    if not all_subs:print("[!] No subdomains collected from any source. Exiting.");return
    root_domains.update(get_root_domains(all_subs))
    c99_subs=query_c99(list(root_domains))
    print(f"[*] Found {len(c99_subs)} subdomains from C99.")
    all_subs.update(c99_subs)
    if run_shodan:
        shodan_subs=query_shodan_comprehensively(list(root_domains))
        print(f"[*] Found {len(shodan_subs)} subdomains from Shodan.")
        all_subs.update(shodan_subs)
    print(f"\n[*] Total unique subdomains collected: {len(all_subs)}")
    save_final_output(all_subs,final_txt,final_zip)
    if run_httpx:run_httpx_scan_with_shell(final_txt,final_httpx)
    print("[*] Cleaning up intermediate data directories...")
    if Path(ZIP_DIR).exists():shutil.rmtree(ZIP_DIR)
    if Path(EXTRACT_DIR).exists():shutil.rmtree(EXTRACT_DIR)
    print("[✓] Cleanup complete.")

# --- Entry Point ---
if __name__=='__main__':
    print(ASCII_BANNER);print(f"       {SCRIPT_NAME}\n")
    print("--------------------------------------------------------------------------------")
    print(f"       {AUTHOR}")
    print("--------------------------------------------------------------------------------\n")
    
    parser=argparse.ArgumentParser(description="One Snap CLI",formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-p","--program",nargs='+',help="Target specific program(s) by name (e.g., tesla, dell). Overrides platform flags.")
    parser.add_argument("--private",help="Path to a text file with private subdomains.")
    parser.add_argument("--shodan",action="store_true",help="Use the comprehensive, multi-query Shodan method.")
    parser.add_argument("--rerun-chaos",action="store_true",help="Force re-download of all Chaos Project data (ignores all filters).")
    parser.add_argument("--httpx",action="store_true",help="Run your specified httpx command on the final list.")
    pg=parser.add_argument_group('Bounty Platforms (Optional, ignored if --program is used)')
    pg.add_argument("-bugcrowd",action="store_true");pg.add_argument("-h1",action="store_true",dest="hackerone");pg.add_argument("-intigriti",action="store_true");pg.add_argument("-yeswehack",action="store_true");pg.add_argument("-hackandproof",action="store_true",dest="hackenproof")
    
    if GUI_AVAILABLE and'DISPLAY'in os.environ and len(sys.argv)==1:
        root=tk.Tk();OneSnapGUI(root);root.mainloop()
    else:
        if len(sys.argv)==1:
            parser.print_help(sys.stderr)
            sys.exit(1)
            
        args=parser.parse_args()
        platforms=[p for p,a in[("bugcrowd",args.bugcrowd),("hackerone",args.hackerone),("intigriti",args.intigriti),("yeswehack",args.yeswehack),("hackenproof",args.hackenproof)]if a]
        if not any([args.program,args.private,args.rerun_chaos,platforms]):
            parser.error("No data source specified. Please provide a program (-p), private list (--private), platform (-bugcrowd, etc.), or use --rerun-chaos.")
        run_one_snap(args.program,args.private,args.rerun_chaos,args.httpx,args.shodan,platforms)
