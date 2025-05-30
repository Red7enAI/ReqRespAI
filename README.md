# ReqRespAI

![image](https://github.com/user-attachments/assets/cbcaf5d4-53a1-49d6-95d9-d99c86e9081b)


<h3>****** DISCLAIMER ****************************************************************

This application is for EDUCATIONAL PURPOSES ONLY.                           

Do not perform any actions on a domain for which you do not have PERMISSION. 

These actions also include any passive scans on a domain                     

Red7en, LLC is not responsible for any illegal activities you may perform.   

**********************************************************************************</h3>

This application uses a local LLM of your choice running under Ollama to search for OWASP Top 10 vulnerabilities.  

The effectivness of this application depends on the LLM you choose to search for vulnerabilities and suggest possible exploits.

<b>If you agree and understand to the above, continue reading.</b>

The application consists of these 4 important files:

The first two files are extensions to ZAP and Burp Suite to write all Requests
and Responses to a JSON file.  Ensure you have write access to that location!
1) ZAPTrafficLogger.py  (To be installed in ZAP if ZAP is your Proxy Server)
2) BurpTrafficLogger.py (To be installed in Burp Suite if it is your Proxy Server)
3) config.txt - Contains values for how the main program should run
4) ReqRespAnalysis.py - The main program that will pass each Request and Response to the LLM for Analysis

<b>Initial Setup:</b>

1) Install Ollama on your computer.  https://ollama.com/download
2) Once Ollama is installed, install locally an LLM of your choice at https://ollama.com/search
3) If not already installed, install Python version 3.x at https://www.python.org/downloads/
4) If not already installed, perform a pip install of these modules
  * json 
  * subprocess
  * time
  * os
  * csv  
  * If using Burp Suite, also burp
5) Depending on the Proxy Server of your choice, modify either BurpTrafficLogger.py (line 37) or ZAPTrafficLogger.py (line 28) to specify the file where the Requests and Responses will be written
6) Modify config.txt to specify 
  * The local LLM Model of your choice 
  * The file specified in Step 5


<b>If using ZAP as Proxy Server:</b>
* Install ZAPTrafficLogger.py as a StandAlone Script
* Collect some Requests and Responses
* When complete, run the ZAPTrafficLogger script to produce a JSON formatted file

<b>If using Burp Suite as Proxy Server</b>
* Install BurpTrafficLogger.py and load it
* Scan a website<

<b>Once the output file from either ZAP or Burpsuite has been created:</b>
* Verify your settings in config.sys
* run python ReqRespAnalysis.py
* Review Configuration settings being used
* Enter number of entries to skip.  Start from non-0 if this is a restart.

<b>Output files to review:</b>
vulnerability_summary.csv 
    A summarized list of the analysis that the LLM performed and any suggested exploits
rejected_entries.json
    A file of rejected requests or responses.
    You may want to rerun ReqRespAnalysis.py for these rejected entries


<h4>For support email wardellcastles@red7en.com</h4>
