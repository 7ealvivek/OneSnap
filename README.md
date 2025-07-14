
# One Snap: The Universal Bounty Subdomain Harvester

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Dependencies](https://img.shields.io/badge/dependencies-requests%2C%20tqdm%2C%20slack_sdk%2C%20httpx-green.svg)
![GUI Availability](https://img.shields.io/badge/GUI-Tkinter-brightgreen.svg)

[![imag.png](https://i.postimg.cc/Qt35Q3C0/imag.png)](https://postimg.cc/xk6cQBKz)

One Snap is a powerful, all-in-one subdomain enumeration tool designed for bug bounty hunters and penetration testers. It intelligently gathers and enriches subdomain data from multiple sources to provide a comprehensive and accurate final list, while prioritizing stability and safe API usage.

This tool automates the tedious process of collecting subdomains from public datasets and enriching them with deep, recursive lookups, allowing you to focus on finding vulnerabilities, not on managing data.

---

## 🔥 Features

- **Multi-Source Enumeration**: Gathers subdomains from the massive [ProjectDiscovery Chaos dataset](https://chaos.projectdiscovery.io/), the [C99.nl API](https://c99.nl/api), and a comprehensive multi-query [Shodan](https://www.shodan.io/) search.
- **Targeted & Bulk Scanning**:
    -   `-p, --program`: Target a specific program by name (e.g., `tesla`, `dell`) for fast, focused scans.
    -   
    -   `-bugcrowd, -h1, etc.`: Scan all programs on a specific bug bounty platform.
    -   
    -   `--private`: Use your own custom list of domains as a starting point.
- **Intelligent Enrichment**: Automatically extracts root domains from all collected data and uses them for further deep dives with C99 and Shodan.
- **Safe & Reliable API Usage**:
    -   **Strict Rate-Limiting**: Hard-coded delays on all API calls (C99 and Shodan) to guarantee you will not be blocked or rate-limited.
    -   **Robust Error Handling**: Gracefully handles API failures and provides a clean summary of any domains that could not be processed, ensuring the script never crashes mid-scan.
- **Live Host Discovery**: Integrates with [**`httpx`**](https://github.com/projectdiscovery/httpx) to perform a fast, post-scan discovery of which subdomains are live and responding.
- **Smart File Management**: Automatically creates uniquely named output files (e.g., `dell_subs.txt`, `bugcrowd_subs.zip`) so you never overwrite previous results.
- **Self-Contained & User-Friendly**:
    -   **Automatic Dependency Installation**: Checks for and installs required Python packages on first run.
    -   **Cross-Platform GUI**: Includes an optional, easy-to-use graphical interface for users on desktop environments.

---

## ⚙️ Installation & Setup


One Snap is designed to be as simple as possible to set up.

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/7ealvivek/OneSnap.git
    cd OneSnap
    ```

2.  **Install External Tools (Required):**
    The script uses `httpx` for live host discovery. It must be installed and in your system's PATH.
    ```bash
    # Requires Go language to be installed
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    ```

3.  **Set Your API Keys:**
    Open the `OneSnap.py` file in a text editor and add your API keys to the configuration section at the top.
    ```python
    # --- API Keys ---
    C99_API_KEY = "YOUR-API-KEY" # Replace with your key IMPORTANT
    SHODAN_API_KEY = "YOUR-API-KEY" # Replace with your key if OPTIONAL ( IT INCREASES THE SUBDOMAIN COUNT SIGNIFICANTLY )
    ```

4.  **Run the Script:**
    The first time you run the script, it will automatically install all necessary Python packages (`requests`, `tqdm`, `tldextract`, `shodan`).
    
    ```bash
 python3 OneSnap.py --help

```    
     ___````````````````````______```````````````````````````
`.'````.````````````````.'`____`\``````````````````````````
/``.-.``\`_`.--.``.---.`|`(___`\_|_`.--.```,--.``_`.--.```
|`|```|`|[``.-.`|/`/__\\`_.____`.`[``.-.`|``'_\`:[`'/'`\`\`
\```-'``/`|`|`|`|`||`\__.,|`\____)`|`|`|`|`|`//`|`|,|`\__/|`
``.___.'`[___||__]'.__.'`\______.'[___||__]\'-;__/|`;.__/``
`````````````````````````````````````````````````[__|``````

       One Snap: The Universal Bounty Subdomain Harvester

--------------------------------------------------------------------------------
       x.com/starkcharry | github.com/7ealvivek | bugcrowd.com/realvivek
--------------------------------------------------------------------------------
```

```
```
```
usage: test12.py [-h] [-p PROGRAM [PROGRAM ...]] [--private PRIVATE] [--shodan] [--rerun-chaos] [--httpx] [-bugcrowd] [-h1] [-intigriti] [-yeswehack] [-hackandproof]

One Snap CLI

options:
  -h, --help            show this help message and exit
  -p PROGRAM [PROGRAM ...], --program PROGRAM [PROGRAM ...]
                        Target specific program(s) by name (e.g., tesla, dell). Overrides platform flags.
  --private PRIVATE     Path to a text file with all private programs subdomains.
  --shodan              Use the comprehensive, multi-query Shodan method.
  --rerun-chaos         Force re-download of all Chaos Project data (ignores all filters).
  --httpx               Run your specified httpx command on the final list.

Bounty Platforms (Optional, ignored if --program is used):
  -bugcrowd
  -h1
  -intigriti
  -yeswehack
  -hackandproof
  ```
    ```

    # PLEASE MAKESURE TO USE THE TOOL UNDER THE SCREEN COMMAND OF ANY VPS, BECAUSE IT TAKES TIME TO DOWNLOAD ALL THE LAKHS OF SUBDOMAINS AVAILABLE ( APPROX MAX TIME 2-3 HOURS ) TO COMPLETE

---

## 🚀 Usage

The script requires at least one data source to be specified.

### **Basic Examples**

#### Target a Specific Program
This is the most common use case. The `-p` flag will search the Chaos dataset for any program name containing your keyword.

*   **Find subdomains for Public Targets eg;. Dell, T-mobile etc:**
    ```bash
    python3 OneSnap.py -p dell
    ```
*   **Find subdomains for multiple programs:**
    ```bash
    python3 OneSnap.py -p "t-mobile" shopify
    ```

#### Target a Bug Bounty Platform
Use flags to gather subdomains for all programs on a platform.

*   **Get all Bugcrowd programs:**
    ```bash
    python3 OneSnap.py -bugcrowd
    ```
*   **Get all HackerOne, Bugcrowd & Intigriti etc programs:**
    ```bash
    python3 OneSnap.py -h1 -intigriti -bugcrowd -h1
    ```

#### Use a Private List 

# # ( Load your Pvt Program list domain/subdomain, any format, it will run c99 & Shodan over root domains and increase your attack surface by 20-30% )

Scan only the domains/subdomains from a local file. This will not download any public data unless another flag is used.

```bash
# Create your list
echo "private-program-scope.com" > my_private_program_subdomain_list.txt
echo "meta.com" >> my_private_program_subdomain_list.txt

# Run the scan
python3 OneSnap.py --private my_private_program_subdomain_list.txt --shodan
```

### **Advanced Usage with Enrichment & Post-Processing**

Combine flags for a powerful, automated workflow.

#### Add Shodan Enrichment
The `--shodan` flag enables the comprehensive, multi-query Shodan scan on all discovered root domains.

```bash
# Get all Tesla subs from Chaos and enrich them with Shodan
python3 OneSnap.py -p tesla --shodan
```

#### Find Live Hosts
The `--httpx` flag runs your custom `httpx` command on the final, collected subdomain list.

```bash
# Get all Bugcrowd subs and find the live ones
python3 OneSnap.py -bugcrowd --httpx
```

#### The Ultimate Workflow
Combine all features for a full-spectrum enumeration.
```bash
# 1. Get all subs for "Dell" from Chaos
# 2. Add subs from your private list
# 3. Enrich both with the comprehensive Shodan scan
# 4. Find all live hosts with httpx
python3 OneSnap.py -p dell --private my_servers.txt --shodan --httpx
```

### Using with `proxychains4`

To route all network traffic (Chaos, C99, Shodan) through a proxy, prepend `proxychains4` to your command. **Note:** This will significantly increase scan time.

```bash
# Make sure /etc/proxychains4.conf is configured (e.g., with Tor)
# socks5  127.0.0.1 9050

proxychains4 python3 OneSnap.py -p verizon --shodan
```
---

## Contributing

Contributions are welcome! If you have suggestions, bug reports, or want to contribute code, please feel free to:

1.  Open an issue on the GitHub repository.
2.  Fork the repository and submit a pull request.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author & Credits

Developed by **Vivek Kashyap** | [bugcrowd.com/realvivek](https://bugcrowd.com/realvivek)

Special thanks to:
*   [ProjectDiscovery](https://projectdiscovery.io/) for the amazing Chaos Project and `httpx` tool.
*   [C99.nl](https://c99.nl/) for their valuable subdomain discovery API.

---

<p align="left">
  <strong>Connect with the Author:</strong><br>
  X (Twitter): [@starkcharry](https://x.com/starkcharry)<br>
  Bugcrowd: [bugcrowd.com/realvivek](https://bugcrowd.com/realvivek)<br>
  GitHub: [@7ealvivek](https://github.com/7ealvivek)
</p>

