import os
import hashlib
import vt
from discord_webhook import DiscordWebhook
import time
# the goal of this project is to auto scan the user's downloads folder and check each new file on virustotal
# for any anomalies, then use a discord webhook for alerts

# what it needs to do:
# 1. get the number of items in the downloads folder
# 2. get the latest item
# 3. get the file hash of the latest item
# 4. loop that checks every X minutes. Number is arbitrary but make sure you don't get rate limited
# 5. discord webhook notifs

downloads_path = r"INSERT_FILE_PATH_HERE"
client = vt.Client("YOUR_VIRUSTOTAL_API_KEY")
# the above creates a client in virustotal using my private api key
DISCORD_WEBHOOK_URL = "INSERT_WEBHOOK_URL_HERE"

#function to get number of files in downloads folder
def filescount(path):
    filecount = 0
    for itemname in os.listdir(path):
        # when you print path, each line is a unique file
        # note: os.path.isfile checks if a given path is a file or not
        # note: os.path.join combines filenames and paths into a valid path
        # note: this checks only the number of FILES not directories in the given path
        if os.path.isfile(os.path.join(path, itemname)):
            # for debugging
            # print(path)
            filecount+=1 # adds 1 to filecount
        else:
            continue
    return filecount #use return to make scripting better

#function to get most recent file
def mostrecentfile(path):
    # use os.path.getmtime(path)
    allfiles = os.listdir(path) # gets a list of all entries in a directory
    fileslist = [] # initialize empty list
    for filename in allfiles: # filename is an arbitrary name. BUT allfiles is the entire list of files
        fullpath = os.path.join(path, filename) # recreate full file path
        if os.path.isfile(fullpath): # checks if fullpath is a file
            fileslist.append(fullpath) # if it is a file, then append said path into the fileslist
    mostrecentfile = max(fileslist, key = os.path.getmtime)
    #the max function has a thing called key =
    # which lets you find the max value based on what the key variable returns
    # so: max ( SOURCE , FILE MOD TIME )
    return mostrecentfile
#get file hash function
def getsha256hash(path):
    with open(path, "rb") as file:
        bytes = file.read()
        hashvalue = hashlib.sha256(bytes).hexdigest()
    return hashvalue

# find data from virustotal
def checkfile(hash): # "This is where the fun begins" -Anakin Skywalker
    # example: file = client.get_object("/files/44d88612fea8a8f36de82e1278abb02f")
    # the above lets you search based on hash alone
    # NOTE: this assumes the file in question is fairly common. May require file upload functionality later
    try:
        file = client.get_object(f"/files/{hash}") # send hash to VT
        # if successful, return the data. Note: the 0 down there is the default value. this changes if
        return file.last_analysis_stats.get('malicious', 0)
    except vt.APIError as e:
        print(e)
        
# DEBUG:
#downloads_count = filescount(downloads_path)
# print(f"{downloads_count} files in downloads folder. ")
# print(f" {mostrecentfile(downloads_path)} is the most recent file. ")
# print(f" and its sha256 hash is {getsha256hash(mostrecentfile(downloads_path))}")
# print(f" and its maliicous score on VT is: {checkfile(getsha256hash(mostrecentfile(downloads_path)))}/64")

# hash for empty file. Debug purposes
#print(f"{checkfile("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")}")

while (True):
    baseline = 583 # this is a hardcoded value for the "baseline". Anything greater than this will signal
    # a scan on VT. TODO: add dynamically updating baseline for detection
    filecount_tmp = filescount(downloads_path)
    if filecount_tmp > baseline: # this essentially means that there's a new file
        # stuff
        malicious_score = checkfile(getsha256hash(mostrecentfile(downloads_path)))
        if malicious_score > 5:
            print('thing')
            #send discord notif
            webhook = DiscordWebhook(url=DISCORD_WEBHOOK_URL, content = f"@everyone {mostrecentfile(downloads_path)} is malicious!")
            response = webhook.execute()
    # add a delay of X minutes down here
    time.sleep(300)
