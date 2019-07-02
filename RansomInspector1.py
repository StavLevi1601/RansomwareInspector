import requests
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os
import sys
import argparse
from selenium import webdriver
import datetime
import re

ABS_SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
#DEFAULT_COMMIT = "Configuration Change"
#CRAD_FILE = "Card.dat"


# ///////////////////////////////////////////////////////////////////////////
# read_text
# //////////////////////////////////////////////////////////////////////////

def read_text(xpath, sleep_time, driver):
    #fields = wait.until(EC.presence_of_all_elements_located((By.XPATH, xpath))) #contains elemnts of XPATH
    fields = driver.find_elements_by_xpath(xpath)
    for field in fields:
        print(field.text)
    time.sleep(sleep_time)
    return field

# ///////////////////////////////////////////////////////////////////////////
# get all sha's
# //////////////////////////////////////////////////////////////////////////

def get_sha_from_link_list(link_list):
    sha_list = []
    for link in link_list:
        sha_list.append(re.findall(r"virustotal\..*\/\w+\/\w+/(\w+)\/", link))
    return sha_list

# ///////////////////////////////////////////////////////////////////////////
# get all Data //link and data
# //////////////////////////////////////////////////////////////////////////

def get_all_Data(driver , field, sleep_time):
    url_list = []
    from selenium.webdriver.common.keys import Keys
    for f in field:
        current_url = driver.current_url #i want to get the current url
        f.send_keys(Keys.CONTROL + Keys.ENTER) #open a new tab
        time.sleep(sleep_time) #uploding the page
        try:
         driver.switch_to.window(driver.window_handles[1]) #replace to the next tab
         get_extension_from_id_ransomware(sleep_time, driver)
         get_read_me(sleep_time,driver)
         url_list.append(driver.current_url) #here we get the currnt new url
         driver.close() #closing the tab
         driver.switch_to.window(driver.window_handles[0]) #switch to the first
        except:
            continue
    return url_list

# ///////////////////////////////////////////////////////////////////////////
# get all links
# //////////////////////////////////////////////////////////////////////////

def get_all_links(driver , field, sleep_time):
    url_list = []
    from selenium.webdriver.common.keys import Keys
    for f in field:
        current_url = driver.current_url #i want to get the current url
        f.send_keys(Keys.CONTROL + Keys.ENTER) #open a new tab
        time.sleep(sleep_time) #uploding the page
        try:
         driver.switch_to.window(driver.window_handles[1]) #replace to the next tab
         url_list.append(driver.current_url) #here we get the currnt new url
         driver.close() #closing the tab
         driver.switch_to.window(driver.window_handles[0]) #switch to the first
        except:
            continue
    return url_list

# ///////////////////////////////////////////////////////////////////////////
# get all extension's
# //////////////////////////////////////////////////////////////////////////


def get_extension_from_id_ransomware(sleep_time, driver):
    try:
        read_me_arr = read_text(r'//span[contains(text(),"записка")]/b', sleep_time, driver)
        print(read_me_arr)
        return read_me_arr
    except:
        return ""

# ///////////////////////////////////////////////////////////////////////////
# get rensome sha
# //////////////////////////////////////////////////////////////////////////

def get_ransome_comments_sha(shas):
    comments_url = r"https://www.virustotal.com/ui/files/{}/comments"
    ransome_sha = []
    import requests
    for sha in shas:
        time.sleep(5)
        comment_url = comments_url.format(sha)
        req = requests.get(url=comment_url)
        data_json = req.json()
        if "#ransomware" in data_json['data'][0]['text']:
            ransome_sha.append(sha)
    return ransome_sha

# ///////////////////////////////////////////////////////////////////////////
# get note is called - Read ME
# //////////////////////////////////////////////////////////////////////////

def get_read_me(sleep_time, driver):
    try:
        extension_arr = read_text(r'//span[contains(text(),"записка")]/b/span', sleep_time, driver)
        print(extension_arr)
        return extension_arr
    except:
        return ""


# ///////////////////////////////////////////////////////////////////////////
# get ssdeep
# //////////////////////////////////////////////////////////////////////////

def get_ssdeep(sha):
    json_url = r"https://www.virustotal.com/ui/files/{}".format(sha)
    import requests
    time.sleep(5)
    req = requests.get(url=json_url)
    data_json = req.json()
    return data_json['data']['attributes']['ssdeep']

# ///////////////////////////////////////////////////////////////////////////
# Run WebDriver
# //////////////////////////////////////////////////////////////////////////

def run(commit):
    sleep_time = 0.5
    driver = webdriver.Chrome(r"C:\Driver\chromedriver.exe")
    wait = WebDriverWait(driver, 10)
    driver.get('http://id-ransomware.blogspot.com/2019/01/crypt0r-ransomware_10.html')

    all_urls = wait.until(EC.presence_of_all_elements_located((By.XPATH, r"//li/a[contains(@href,'http://id-ransomware.blogspot.com/2019/')]")))

    # Here is the place that all the tables are open - put commit on all the block use CTRL / for comment

    list_of_all_links = get_all_Data(driver, all_urls, sleep_time)

    vt_link_list = []
    for link in list_of_all_links:
         try:
             field = wait.until(EC.presence_of_all_elements_located((By.XPATH, r"//b/a[contains(@href,'https://www.virustotal.com')]")))
             list = get_all_links(driver, field, sleep_time)
             vt_link_list = vt_link_list + list
             ssdeep = get_ssdeep(wait)
         except:
             continue

    #vt_link_list = ['https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535', 'https://www.virustotal.com/gui/file/89f35f20af62201010e3218a22c50ed6994c79fb6f9f2210fd55203e6e6b01a1/detection', 'https://www.virustotal.com/gui/file/08184f452cccd8ab7e3908b85e6a69cda9afe46c4a09dbadad0846eff37ae535/detection']
    shas = get_sha_from_link_list(vt_link_list)

    #ransome_shas = get_ransome_sha(shas)

    with open("ransome_repoert.csv", 'w') as f:
        f.write("shas: \n")
        shas=''.join(str(e) for e in shas)
        #f.write(shas, sep = ", ")
        f.write("ransome_sha: \n")
      #  f.write(ransome_shas, sep=", ")
        f.write("ssdeep:\n")
        ssdeep = ''.join(str(i) for i in ssdeep)
        f.write("note read me:\n")


# /////////////////////////////////////////////////////////////////////////
# parse_input_args
# <INPUT - args>                             Args object
# <RETURN VALUE - parser.parse_args(args)>   All the arguments that been parsed
# ////////////////////////////////////////////////////////////////////////

def parse_input_args(args):
    parser = argparse.ArgumentParser(
        description='This tool is automation to create a pull request')
    parser.add_argument('-s', '--sha',
                        help='get sha')
    return parser.parse_args(args)

# ///////////////////////////////////////////////////////////////////////////
# Main
# //////////////////////////////////////////////////////////////////////////

def main(args):
    argv = parse_input_args(args)

    if argv.sha:
        sha = argv.sha
        ssdeep = get_ssdeep(sha)
        print(ssdeep)
        return
    else:
        sha = ""

    run(sha)

if __name__ == "__main__":
    main(sys.argv[1:])



