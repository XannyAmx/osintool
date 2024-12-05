# Osintool

Osintool is a tool that makes it easy to search and download files from Google and Wayback Machine.

This framework can be used to search for subdomains of a main domain. In addition, it generates a summary about the (sub)domain with DNS and WHOIS lookup.

# Installation

Osintool is specially designed to be installed and run on a Linux operating system.
```bash
git clone https://github.com/xannyamx/osintool.git
cd osintool
pip3 install -r requirements.txt
python3 osintool.py
```

# Using Osintool

![image](https://github.com/user-attachments/assets/9689b405-27a5-4996-8ffe-8088931d1f2c)

Parameters:    
    -o (Wayback Machine search)  
    -g (Google search)  
    -d example.com,example2.com (Main domain)  
    -t <0...999> (ONLY WITH USE OF -o, maximum search time in years)  
    -w wordlist.txt (ONLY WITH USE OF -o, wordlist of subdomains)  
    -f <type file> (ONLY WITH USE OF -g, type of file to be searched)  
    -k <key> (ONLY WITH USE OF -g, Google API key)  
    -c <cx> (ONLY WITH USE OF -g, Programmable search engine)  

# Examples of use

  Wayback Machine search:
```bash
python3 osintool.py -o -d example.com -t 2 -w wordlist.txt
```
![image](https://github.com/user-attachments/assets/9c643a90-5076-45a0-97de-f3b3d8e10cb4)
Example of main domain summary:
![image](https://github.com/user-attachments/assets/0a048150-ee25-4414-b161-b8f9996102a6)
  Google search:
 ```bash
 python3 osintool.py -g -k <key> -c <cx> -d example.com -f pdf
```
![image](https://github.com/user-attachments/assets/bd43e67b-531a-46fd-b904-1393bca85ccf)

# Disclaimer
This program is published to be used for educational purposes. I am not responsible for any misuse of this project.

# Contact

[dannyms2203@gmail.com](mailto:dannyms2203@gmail.com)
