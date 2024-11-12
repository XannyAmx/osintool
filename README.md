# Osintool

Osintool is a tool that makes it easy to search and download files from Google and Wayback Machine.

This framework can be used to search for subdomains of a main domain. In addition, it generates a summary about the (sub)domain with DNS and WHOIS lookup.

# Installation

Osintool is specially designed to be installed and run on a Linux operating system.
```
git clone https://github.com/xannyamx/osintool.git
cd osintool
pip install -r requirements.txt
./osintool.py
```

# Using Osintool

![image](https://github.com/user-attachments/assets/edeb8cec-d377-4be8-967a-1a8383548d63)


Parameters:    
    -o (Wayback Machine search)  
    -g (Google search)  
    -d example.com (Main domain)  
    -t <0...999> (ONLY WITH USE OF -o, maximum search time in years)  
    -w wordlist.txt (ONLY WITH USE OF -o, wordlist of subdomains)  
    -f <type file> (ONLY WITH USE OF -g, type of file to be searched)  
    -k <key> (Google API key)  
    -c <cx> (Programmable search engine)  

# Examples of use

  Wayback Machine search:
```
python3 osintool.py -o -d example.com -t 10 -w wordlist.txt
```
![image](https://github.com/user-attachments/assets/5b21a81f-476a-46bb-ae0f-6236c59153ca)

  Google search:
 ```
 python3 osintool.py -g -d example.com -f pdf -k <key> -c <cx>
```
![image](https://github.com/user-attachments/assets/7697733b-5115-4528-9385-e5e2783e9d9a)


# Disclaimer
This program is published to be used for educational purposes. I am not responsible for any misuse of this project.

# Contact

[dannyms2203@gmail.com](mailto:dannyms2203@gmail.com)
