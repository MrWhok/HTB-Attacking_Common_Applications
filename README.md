# HTB-Attacking_Common_Applications

## Table of Contents
0. [Tools](#tools)
1. [Setting the Stage](#setting-the-stage)
    1. [Application Discovery & Enumeration](#application-discovery--enumeration)

## Tools
### Enumeration and Discovery
- Nmap
- eyewitness
- nessus
- aquatone

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

