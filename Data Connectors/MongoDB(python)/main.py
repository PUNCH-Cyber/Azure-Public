'''
    TITLE:          MongoDB Atlas Data Connector for Microsoft Sentinel
    VERSION:        1.1
    LAST MODIFIED:  02/06/2022
    AUTHOR:         @punchcyber.com
    
    LATEST UPDATES:
        * Changed the module used for integration with Azure Storage tables to azure-data-tables
    
    DESCRIPTION:
    The following data connector retrieves the following log types from MongoDB Atlas API, transforms the data and pushes to the Log Ananlytics workspace for consumption by Microsoft Sentinel:
        * Org Events                https://docs.atlas.mongodb.com/reference/api/events-orgs-get-all/
        * Project Events            https://docs.atlas.mongodb.com/reference/api/events-projects-get-all/
        * Audit Logs                https://docs.atlas.mongodb.com/reference/api/logs/
        * Cluster Access Logs       https://docs.atlas.mongodb.com/reference/api/access-tracking-get-database-history-clustername/ 

    REQUIRED VARIABLES:
        * debug - (true/false) verbose logging toggle
        * publicKey - MongoDB API username/public key
        * privateKey - MongoDB API password/private key
        * timeInterval - initial log event lookback timeframe (in minutes)
        * workspaceId - Log Analytics workspace Id
        * workspaceKey - Log Analytics workspace key
    
    MONGODB ATLAS API LIMITATIONS:
        * 100 API requests per minute, per Project
        * Maximum records per API response is 500
        * Cluster Access Logs: a) maximum record is set to 2000, no header info is returned in the API response, this information would provide any pagningation information, any records past 2000 events will be lost.

'''
import requests
import json
import logging
import hashlib
import hmac
import base64
import time
import os.path
import gzip
import math

from datetime import datetime, timedelta
from requests.auth import HTTPDigestAuth
from azure.data.tables import TableServiceClient

################################################################################################
# VARIABLES
################################################################################################

# MongoDB Atlas API Variables
publicKey = os.environ["publicKey"]
privateKey = os.environ["privateKey"]
baseUrl = "https://cloud.mongodb.com/api/atlas/v1.0"
timeInterval = os.environ["timeInterval"] # the last 'x' minutes (e.g. 5 = the last 5 mins)
end_time = datetime.strftime(datetime.utcnow(), '%Y-%m-%dT%H:%M:%S')
debug = os.environ["debug"]
# Define the number of events per API response, limits: up to 500. Lower the record limit risks API request limitations. This limit does not apply to Audit Logs
responseRecordLimit = 500
# Compile Credentials
auth = HTTPDigestAuth(publicKey, privateKey)
dateFormat = '%Y-%m-%dT%H:%M:%S'

# Log Analytics Variables
workspaceId = os.environ["workspaceId"]
workspaceKey = os.environ["workspaceKey"]
tableName = "MongoDB"
TimeStampField = "DateValue"

# General Variables
# General Variables
checkpointTable = "AtlasAPICheckpoints"
azureBlobStorageUrl = os.environ["AzureWebJobsStorage"] # leverage the storage account created with the Function App


################################################################################################
# GENERAL FUNCTIONS
################################################################################################

# Configure logging levels
def configure_logger():
    """
    Generates basic logger at either debug or info level
    """
    if "debug" in os.environ and os.environ["debug"] == True:
        log_level = "debug"
    else:
        log_level = "info"

    format = "%(levelname)s: %(message)s"
    logging.basicConfig(format=format, level=log_level.upper())
    
# Generation of unique row key for checkpoint recordd
def generate_md5_hash(logType, orgId = "", groupId = "", clusterName = "", hostname = "", filename = ""):
    
    concat_str = logType + orgId + groupId + clusterName + hostname + filename
    md5 = hashlib.md5(concat_str.encode())
    return md5.hexdigest()

# Retrieves the start time based on the checkpoint file
def get_start_time (logType, endTime, orgId = "", groupId = "", clusterName = "", hostname = "", filename = "", atlasRespStatus = "", postRespStatus = ""):

    endTime = datetime.strptime(endTime, dateFormat)
    start_time = endTime - timedelta(minutes=timeInterval)
    firstStartTimeRecord = datetime.strftime(start_time, dateFormat)
    
    table_service = TableServiceClient.from_connection_string(conn_str=azureBlobStorageUrl)
   # Create checkpoint table if it does not exist
    table_service.create_table_if_not_exists(table_name=checkpointTable)
    table_client = table_service.get_table_client(table_name=checkpointTable)
    rowKey = generate_md5_hash(logType, orgId, groupId, clusterName, hostname, filename)
        
    # Check for an existing checkpoint entry
    try:
        existingEntry = table_client.get_entity(partition_key=logType, row_key=rowKey)
    except Exception:
        existingEntry = None
    
    if existingEntry:
        logging.info("[{}]: orgId={};groupId={};clusterName={};hostname={};filename={};msg=Last Successful Time Checkpoint Entry Found".format(logType, orgId, groupId, clusterName, hostname, filename))   
        return existingEntry['lastSuccessTime']
    
        # if the record is not found, create a new record and use the interval time as the start time
    else:
        newCheckpointEntry = {
            'PartitionKey': logType,
            'RowKey': rowKey,
            'orgId': orgId,
            'groupId': groupId,
            'clusterName': clusterName,
            'lastSuccessTime': firstStartTimeRecord,
            'hostname': hostname,
            'filename': filename,
            'atlasRespStatus': atlasRespStatus,
            'postRespStatus': postRespStatus
        }
            
        table_client.create_entity(entity=newCheckpointEntry)            
        logging.info("[{}]: orgId={};groupId={};clusterName={};hostname={};filename={};msg=New Checkpoint Entry Added".format(logType, orgId, groupId, clusterName, hostname, filename))
        
        return firstStartTimeRecord

# Updates the checkpoint entry based on the log type
def update_checkpoint_entry(logType, lastSuccessTime = "", orgId = "", groupId = "", clusterName = "", hostname = "", filename = "", atlasRespStatus = "", postRespStatus = ""):
    
    table_service = TableServiceClient.from_connection_string(conn_str=azureBlobStorageUrl)
    table_client = table_service.get_table_client(table_name=checkpointTable)
    rowKey = generate_md5_hash(logType, orgId, groupId, clusterName, hostname, filename)

    existingEntry = table_client.get_entity(partition_key=logType, row_key=rowKey)
    if existingEntry:       
        # Update the status of the Atlast API request
        if atlasRespStatus:
            existingEntry['atlasRespStatus'] = atlasRespStatus        
                
        # Update the Last Successful time if there was a successful Atlas API request and successful post to Log Analytics
        if existingEntry['atlasRespStatus'] == "Success" and postRespStatus == "Success":
            existingEntry['lastSuccessTime'] = lastSuccessTime
            existingEntry['postRespStatus'] = "Success"
        elif existingEntry['atlasRespStatus'] == "Failed" and postRespStatus:
            existingEntry['postRespStatus'] = "Failed"
        elif postRespStatus == "Failed":
            existingEntry['postRespStatus'] = "Failed"
            
        table_client.update_entity(entity=existingEntry)
    else:
        logging.error("[{}]: Error finding checkpoint entry to update".format(logType))

# Track the rate of calls made to the MongoDB Atlas API by Group ID   
def api_rate_limit_tracking(groupId):
    
    requestTime = datetime.now()
    previousMin = requestTime - timedelta(minutes=1)
    
    counterEntry = {}
    for i in apiRequestCounter:
        if i['groupId'] == groupId:
            counterEntry = i
            
    counterEntry['requestTimes'].append(requestTime)

    requestInLastMin = 0
    for i in counterEntry['requestTimes']:
        if i > previousMin:
            requestInLastMin += 1

    if requestInLastMin > 95:
        logging.warning("GroupID={} Nearing API Rate Limit, suspending requests for 10 seconds".format(groupId))
        time.sleep(10)

# Calculates play size in MB  
def calculate_obj_size(payload, output, bsize=1024):
    """
    convert bytes to megabytes, etc.
       sample code:
           print('mb= ' + str(bytesto(314575262000000, 'm')))
       sample output: 
           mb= 300002347.946
    """

    bytes = round(len(payload.encode('utf-8')))
    
    a = {'k' : 1, 'm': 2, 'g' : 3, 't' : 4, 'p' : 5, 'e' : 6 }
    r = float(bytes)
    for i in range(a[output]):
        r = r / bsize
        
    return(r)

# Convert time values to an epoch time value
def convert_to_epoch(time):
    time_dt = datetime.strptime(time, dateFormat)
    epoch = int((time_dt - datetime.utcfromtimestamp(0)).total_seconds())
    return epoch

# Function to split JSON payloads greater than the 30MB Log Analytics API limit into chunks
def payload_split(payload, payloadSize, logType):
    
    increment = payloadSize / 30
    groupOf = math.floor(len(payload) / increment) 
    chunks = [payload[i:i + groupOf] for i in range(0, len(groupOf), groupOf)] 
    logging.warning("[{}]: Payload will be broken up into groupings of {} records".format(logType, groupOf))
    
    return chunks

# Convert the decompressed Host Audit logs to JSON for processing
def convert_to_json(raw):
    """
    Converts the raw bytes version of audit logs, which are lines of individual json objects, and converts it to an array of objects that is json compliant

    :param raw:     Raw representation of audit logs
    :return:        Converted audit logs in form of json object array
    """
    decoded = raw.decode("UTF-8")
    result = []
    for each in decoded.splitlines():
        json_repr = json.loads(each)
        result.append(json_repr)
    return result

################################################################################################
# MONGODB ATLAS FUNCTIONS
################################################################################################

# MongoDB Atlas API Requests
def mongodb_atlas_api (logType, startTime, endTime, groupId = "", orgId = "", clusterName = ""):

    # Define request filters and headers
    filters = "includeCount=true&itemsPerPage={}&envelope=true".format(responseRecordLimit)
    timeRange = "minDate={}&maxDate={}".format(startTime, endTime)
    epochStartTime = convert_to_epoch(startTime)
    epochEndTime = convert_to_epoch(endTime)
    headers = {"Content-Type": "application/json"}

    # Define uri based on log type
    if logType == "OrgEvents":
        uri = "{}/orgs/{}/events?{}&{}".format(baseUrl, orgId, filters, timeRange)
    elif logType == "ProjEvents":
        uri = "{}/groups/{}/events?{}&{}".format(baseUrl, groupId, filters, timeRange)
    elif logType == "Clusters":
        uri = "{}/groups/{}/clusters?includeCount=true&envelope=true".format(baseUrl, groupId)
    elif logType == "ClusterAccessLogs":
        uri = "{}/groups/{}/dbAccessHistory/clusters/{}?envelope=true&nLogs=2000&start={}&end={}".format(baseUrl, groupId, clusterName, epochStartTime, epochEndTime)
    else:
       logging.error('LogType parameter not valid. Acceptable values: OrgEvents, ProjEvents, ClusterAccessLogs')
       
    # API Request/Response processing with Pagination
    responseCollection = []
    while uri:
        logging.info("[{}]: Invoking URI: {}".format(logType, uri))
        response = (requests.get(uri, headers=headers, auth=auth)).json()
        
        if groupId:
            api_rate_limit_tracking(groupId)
                
        if 'accessLogs' in response:
            for i in response['accessLogs']:
                responseCollection.append(i)
            logging.info("[{}]: {} record(s) added to the collection".format(logType,len(response['accessLogs'])))
            update_checkpoint_entry(logType, orgId=orgId, groupId=groupId, clusterName=clusterName, atlasRespStatus = "Success")
            uri = None
        elif response['status'] == 200:
            for i in response['content']['results']:
                responseCollection.append(i)
            logging.info("[{}]: {} record(s) added to the collection, {}/{} Total".format(logType,len(response['content']['results']),len(responseCollection), response['content']['totalCount']))
            next_uri = next((i for i in response['content']['links'] if i["rel"] == "next"), None)
            uri = next_uri
            update_checkpoint_entry(logType, orgId=orgId, groupId=groupId, clusterName=clusterName, atlasRespStatus = "Success")
        elif 'error' in response:
            logging.error("[{}]: Unexpected API Response - {};{}".format(logType,response['error'], response['details']))
            update_checkpoint_entry(logType, orgId=orgId, groupId=groupId, clusterName=clusterName, atlasRespStatus = "Failed")
            uri = None
    
    logging.info("[{}]: {} Total Record(s) Found (Time Range: {} - {})".format(logType, len(responseCollection), startTime, endTime))
    return responseCollection

# Download and Decompress Host Audit Logs
def download_audit_logs(logType, groupId, clusterName, hostname, startTime, endTime, filename):
    """
    Requests audit logs for a single host

    Downloads the logs for a particular host and sends them to Splunk

    :param atlas_project_id:    A String representing the project id of the Atlas project whose logs we are downloading
    :param host_name:           A String representing the host name whose logs we are downloading
    :return:                    Decompressed bytes object representation of the logs from server
    """
    
    # Define request filters
    start_time = convert_to_epoch(startTime)
    end_time = convert_to_epoch(endTime)
    headers = {"accept": "application/gzip"}
    
    # Download audit log file
    uri = "{}/groups/{}/clusters/{}/logs/{}.gz?startDate={}&endDate={}".format(baseUrl, groupId, hostname, filename, start_time, end_time)
    logging.info("[{}]: Invoking URI: {}".format(logType, uri))
    response = requests.get(uri, auth=auth, headers=headers)
        
    api_rate_limit_tracking(groupId)

    if 'error' in response:
        logging.info("[{}]: hostname={};filename={});msg=Audit File download failed;error: {}:{}".format(logType, hostname, filename, start_time, end_time, response['error'], response['details']))
        update_checkpoint_entry(logType, groupId=groupId, hostname=hostname, clusterName=clusterName, filename=filename, atlasRespStatus = "Failed")
    else:
        logging.info("[{}]: hostname={};filename={});msg=Audit File downloaded successfully (Time Range: {} - {})".format(logType, hostname, filename, start_time, end_time))
        update_checkpoint_entry(logType, groupId=groupId, hostname=hostname, clusterName=clusterName, filename=filename, atlasRespStatus = "Success")

    decompressed = gzip.decompress(response.content)
    auditLogs = convert_to_json(decompressed)

    return auditLogs

# Function to process, transform and normalize Org Events, Project Events, and Cluster Access Logs
def process_atlas_events(events, logType):
    
    if events:
        eventCollection = []
        for event in events:
            event['logCategory'] = logType
            
            eventCollection.append(event)
            
        return eventCollection
    else:
        return None
    
# Function to process, transform and normalize Audit Logs
def process_audit_logs(events, clusterName, hostname, groupId, filename, logType):
    
    if events:
        eventCollection = []
        for event in events:
            event['logCategory'] = logType
            event['groupId'] = groupId
            event['hostname'] = hostname
            event['clusterName'] = clusterName
            event['filename'] = filename
            
            eventCollection.append(event)
            
        return eventCollection
    else:
        return None

# Pasrse out the hostnames required to download the Host Audit Logs
def parse_host_from_uri(mongoURI):
    """
    Parse host names from URI

    :param mongoURI:    A String representing the mongodb connection uri
    :return:            An array of Strings, each of which is a host in the mongodb cluster represented by the URI
    """
    hosts = []
    split_conn_str = mongoURI.split("//")
    split_conn_str = split_conn_str[1].split(",")
    for host_port in split_conn_str:
        split_host = host_port.split(":")
        hosts.append(split_host[0])
    return hosts

################################################################################################
# LOG ANALYTICS FUNCTIONS
################################################################################################        

# Build the API signature
def build_signature (customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data (customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    return response

# Process payload into JSON format, assess the payload size and POST to log analytics workspace
def loganalytics_dataprocessing(payload, lastSuccessTime, logType, orgId = "", groupId = "", clusterName = "", hostname = "", filename = ""):
    
    if payload:
        # Convert payload to JSON
        body = json.dumps(payload)
        payloadSize = round(calculate_obj_size(body, "m"), 3)
        
        if payloadSize < 30:
            logging.info("[{}]: Posting {} record(s) to Log Analytics workspace: {} MB".format(logType,len(payload), payloadSize))
            response = post_data(workspaceId, workspaceKey, body, tableName)
            
            if response.status_code == 200:
                logging.info("[{}]: SUCCESS: {} records posted to Log Analytics: {} MB".format(logType,len(payload), payloadSize))
                update_checkpoint_entry(logType, lastSuccessTime, orgId, groupId, clusterName, hostname, filename, postRespStatus = "Success")
            else:
                logging.error("[{}]: ERROR: Log Analytics POST unsuccessful: error code={}".format(logType,response.status_code))
                update_checkpoint_entry(logType, lastSuccessTime, orgId, groupId, clusterName, hostname, filename, postRespStatus = "Failed")
                
        # If the payload exceeds 30MB, split the payload into chunks and post to Log Analytics
        else:
            logging.warning("JSON payload execeeded Log Analytics API maximum of 30MB: Total size, {} MB. Initiating function to breakup payload...".format(payloadSize))
            array = payload_split(payload, payloadSize, logType)  
                 
            for i in len(array):                
                if array[i]:
                    array_json = json.dump(array[i])
                    newPayloadSize = round(calculate_obj_size(array_json, "m"), 3)
                    logging.info("[{}]: Posting {} record(s) to Log Analytics workspace: {} MB".format(logType,len(array[i]), newPayloadSize))
                    response = post_data(workspaceId, workspaceKey, array_json, tableName)

                    if (response.status_code >= 200 and response.status_code <= 299):
                        logging.info("[{}]: SUCCESS: {} records posted to Log Analytics: {} MB".format(logType,len(payload), payloadSize))
                        update_checkpoint_entry(logType, lastSuccessTime, orgId, groupId, clusterName, hostname, filename, postRespStatus = "Success")
                    else:
                        logging.error("[{}]: ERROR: Log Analytics POST unsuccessful: error code={}".format(logType,response.status_code))
                        update_checkpoint_entry(logType, lastSuccessTime, orgId, groupId, clusterName, hostname, filename, postRespStatus = "Failed")
    else:
        logging.info("[{}]: orgId={};groupId={};clusterName={};hostname={};filename={};msg=No records were found, processed or posted to the Log Analytics workspace".format(logType,orgId, groupId, clusterName, hostname,filename))
        update_checkpoint_entry(logType, lastSuccessTime, orgId, groupId, clusterName, hostname, filename, postRespStatus = "Success")
            
################################################################################################
# LOG PROCESSING FUNCTIONS
################################################################################################

# Retrieves org events logs from MongoDB Atlas, processes and post to Log Analytics
def etl_org_events(orgs):
    
    logType = "OrgEvents"
    for i in range(len(orgs)):
        orgIds.append(orgs[i]['id'])
        
    logging.info("[Orgs]: {} Org(s) Found".format(len(orgIds)))

    # Determine Time Interval for API request
    for org in orgIds:
        
        # Determine Time Interval for API request
        start_time = get_start_time(logType, end_time, org)
         
        # Retrieve all Org Events
        allOrgEvents = mongodb_atlas_api(logType=logType, orgId=org, startTime=start_time, endTime=end_time)

        # Process, transform, and normalize Org Events
        orgEvents = process_atlas_events(allOrgEvents, logType)
        
        # Pre-post processing and validation then post to Log Analytics workspace
        loganalytics_dataprocessing(orgEvents, end_time, logType, org)

# Retrieves proj events logs from MongoDB Atlas, processes and post to Log Analytics
def etl_proj_events(allProjs):
    
    logType = "ProjEvents"
    
    for proj in allProjs['content']['results']:
        
        # Retrieve checkpoint time
        start_time = get_start_time(logType, end_time, proj['orgId'], proj['id'])
        
        # Add record to track API request per project
        newCounterObj = {
            'groupId': proj['id'],
            'projectName': proj['name'],
            'requestTimes': [],
            'apiRequestsInLastMin': 0
        }
        apiRequestCounter.append(newCounterObj)
        
        # Identify all Clusters within the project
        response = (requests.get("{}/groups/{}/clusters?includeCount=true&envelope=true".format(baseUrl, proj['id']), auth=auth)).json()
        clusters = response['content']['results']
        
        logging.info("[{}]: {} Cluster(s) found in project={};projectName={}".format(logType, len(clusters), proj['id'], proj['name']))
        for i in range(len(clusters)):
            allClusters.append(clusters[i])
            
        # Request all Project Events
        logging.info("[{}]: Processing Project Events for project={};projectName={}".format(logType, proj['id'], proj['name']))
        allProjEvents = mongodb_atlas_api(logType, start_time, end_time, proj['id'], orgId=proj['orgId'])
        
        # Process, transform, and normalize Project Events
        projEvents = process_atlas_events(allProjEvents, logType)
        
        # Pre-post processing and validation then post to Log Analytics workspace
        loganalytics_dataprocessing(projEvents, end_time, logType, proj['orgId'], proj["id"])

# Retrieves cluster access logs from MongoDB Atlas, processes and post to Log Analytics
def etl_cluster_access_logs(clusterList):
    
    logType = "ClusterAccessLogs"
    for cluster in clusterList:
    
        # Retrieve checkpoint time
        start_time = get_start_time(logType, end_time, groupId=cluster['groupId'], clusterName=cluster['name'])
        
        # Request all Cluster Access Logs
        logging.info("[{}]: Processing Cluster Access Logs for {}".format(logType,cluster['name']))
        allClusterAccessLogs = mongodb_atlas_api(logType, start_time, end_time, cluster['groupId'], clusterName=cluster['name'])
        
        # Process, transform, and normalize all Cluster Access Logs
        clusterAccessLogs = process_atlas_events(allClusterAccessLogs, logType)

        # Pre-post processing and validation then post to Log Analytics workspace
        loganalytics_dataprocessing(clusterAccessLogs, end_time, logType, groupId=cluster['groupId'], clusterName=cluster['name'])
        
        # Parse all hostnames from each cluster, utilized to retrieve audit logs
        hostUris = parse_host_from_uri(cluster['mongoURI'])
        for host in hostUris:
            obj = {
                'hostname': host,
                'groupId': cluster['groupId'],
                'clusterName': cluster['name']
            }
            clusterHostnames.append(obj)
            
# Downloads host audit logs from MongoDB Atlas, processes and post to Log Analytics            
def etl_audit_logs(clusterHostnames):
    
    logType = "AuditLogs"
    # Define audit log types
    # auditLogTypes = ['mongodb-audit-log','mongodb']
    auditLogTypes = ['mongodb-audit-log', 'mongodb']
    
    for hostname in clusterHostnames:
    
        # Download and decompress each audit file for the current host in the cluster and post to Log Analuytics
        for filename in auditLogTypes:
            
            # Retrieve checkpoint time
            start_time = get_start_time(logType, end_time, groupId=hostname['groupId'], clusterName=hostname['clusterName'], hostname=hostname['hostname'], filename=filename)
            
            # Download Audit File from Atlas API
            allAuditLogs = download_audit_logs(logType, hostname['groupId'], hostname['clusterName'], hostname['hostname'], start_time, end_time, filename)
            logging.info("[{}]: hostname={};filename={};msg={} Audit events found".format(logType, hostname['hostname'], filename, len(allAuditLogs)))
            
            # Process, transform, and normalize Audit Logs
            auditLogs = process_audit_logs(allAuditLogs, hostname['clusterName'], hostname['hostname'], hostname['groupId'], filename, logType)

            # # Pre-post processing and validation then post to Log Analytics workspace   
            loganalytics_dataprocessing(auditLogs, end_time, logType, groupId=hostname['groupId'], clusterName=hostname['clusterName'], hostname=hostname['hostname'], filename=filename)

################################################################################################
# MAIN SCRIPT
################################################################################################

# Start Processing Marker
start_stop_watch = time.time()

global orgIds
orgIds = []
global allClusters
allClusters = []
global clusterHostnames
clusterHostnames = []
global apiRequestCounter
apiRequestCounter = []

# Identify all Organization Ids
allOrgs = (requests.get(url="{}/orgs?includeCount=true&envelope=true".format(baseUrl), auth=auth)).json()
orgs = allOrgs['content']['results']

# Retrieve all Org Events and post to Log Analytics
etl_org_events(orgs)

# Identify all Projects
allProjs = (requests.get("{}/groups?includeCount=true&envelope=true".format(baseUrl), auth=auth)).json()
logging.info("[Projs]: {} Project(s) Found".format(len(allProjs['content']['results'])))

# Process all Project Events
etl_proj_events(allProjs)

# Process all Cluster Access Logs
etl_cluster_access_logs(allClusters)

# Process all Audit Logs
etl_audit_logs(clusterHostnames)          

# End Processing Marker
end_stop_watch = time.time()
time_lapsed = end_stop_watch - start_stop_watch
logging.info("Total execution time: {} seconds".format(time_lapsed))

################################################################################################
# END SCRIPT
################################################################################################
