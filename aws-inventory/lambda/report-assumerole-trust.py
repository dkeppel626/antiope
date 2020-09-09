import boto3
from botocore.exceptions import ClientError
import json
import os
import time
import datetime
import re
from requests_aws4auth import AWS4Auth
from elasticsearch import Elasticsearch, RequestsHttpConnection
from mako.template import Template

from antiope.aws_account import *
from common import *

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('elasticsearch').setLevel(logging.WARNING)

# Lambda main routine
def handler(event, context):
    logger.info("Received event: " + json.dumps(event, sort_keys=True))
    
    # Data to be saved to S3 and used to generate the template report
    json_data = {"roles": []}
    
    # Get all the active roles from Antiope's ES
    es_role_data = get_role_data_from_es("resources_iam_role")
    
    # Get a list of accounts with "Trusted", "Active" account status from the antiope DynamoDB inventory table.
    trusted_accounts = get_account_ids('TRUSTED')
    suspended_accounts = get_account_ids('SUSPENDED')

    # Get and then sort the list of accounts by name, case insensitive.
    active_accounts = get_active_accounts()
    active_accounts.sort(key=lambda x: x.account_name.lower())

    non_compliant_accounts = []
    
    for a in active_accounts:
        
        # If there are not roles associated with the account, continue on.
        if a.account_id not in es_role_data:
            continue

        else:
            
            for role in es_role_data[a.account_id]:

                # Evaluate the AssumeRolePolicyDocument attached to the role.
                non_compliant_principal = evaluate_assumerole_policy_document(role, active_accounts, trusted_accounts, suspended_accounts)

                # If a role is found to be non compliant.
                if non_compliant_principal:

                    j = {}
                    j['account'] = a.db_record.copy()
                    j['role'] = role
                    
                    json_data['roles'].append(j)
                    non_compliant_accounts.append(a.account_id)

    # Add some summary data for the Template
    json_data['timestamp'] = datetime.datetime.now()
    json_data['non_compliant_role_count'] = len(json_data['roles'])
    json_data['non_compliant_account_count'] = len(set(non_compliant_accounts))
    json_data['bucket'] = os.environ['INVENTORY_BUCKET']

    # Render the Webpage
    fh = open("html_templates/assumerole_trust.html", "r")
    mako_body = fh.read()
    result = Template(mako_body).render(**json_data)

    # Save the JSON to S3
    s3_client = boto3.client('s3')

    try:

        response = s3_client.put_object(
            # ACL='public-read',
            Body=result,
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='text/html',
            Key='Reports/assumerole_trust.html',
        )
        
        response = s3_client.put_object(
            # ACL='public-read',
            Body=json.dumps(json_data, sort_keys=True, indent=2, default=str),
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='application/json',
            Key='Reports/assumerole_trust.json',
        )

    except ClientError as e:
        logger.error("ClientError saving report: {}".format(e))
        raise

    return(event)

def evaluate_assumerole_policy_document(role, active_accounts, trusted_accounts, suspended_accounts):
    
    policy_doc_statement = role['configuration']['AssumeRolePolicyDocument']['Statement']
    non_compliant_principal = []
    
    # Iterate over each policy statement in the list.
    for statement in policy_doc_statement:

        principal = statement['Principal']
        
        for key, value in principal.items():
            
             # Single principals are of type string while multiple principals are of type list.
            if isinstance(value, list):
                principals = value
            else:
                principals = [value]
                    
            # Ignore Roles that have AWS Service Policies.
            if 'Service' in key:
                for principal in principals:
                    if 'amazonaws.com' not in principal:
                        # Something is different append the role so it can be put on the import file and evaluated later.
                        logger.error(f"AssumeRolePolicyDocument Statement contains a non compliant AWS Service Principal:\n {{{key}: {principal}}}")
                        non_compliant_principal.append(principal)
                        
            # Ignore Roles that are SAML/Federated policies, these are evaluated in the IDP inventory/import.
            elif 'Federated' in key:
                pass
        
            # Evaluate each AssumeRole Policy
            elif 'AWS' in key:
                permitted_account = ""
                
                for principal in principals:
                    
                    # Check for the known policy expressions    
                    if principal.startswith('arn:aws:iam::'):
                        permitted_account = re.search('arn:aws:iam::(.*):', principal)
                    elif principal.startswith('arn:aws:sts::'):
                        permitted_account = re.search('arn:aws:sts::(.*):', principal)
                    else:
                        # Something is different, append the role so it can be put on the import file and evaluated later.
                        logger.error(f"AssumeRolePolicyDocument Statement contains a non compliant AssumeRole Principal:\n {{{key}: {principal}}}")
                        non_compliant_principal.append(principal)
                    
                    # Check if the allowed assume role account does not have status of active, suspended, or trusted.
                    if permitted_account:
                        if permitted_account[1] not in str(active_accounts) and permitted_account[1] not in str(trusted_accounts) and permitted_account[1] not in str(suspended_accounts):
                            logger.debug(f"AssumeRolePolicyDocument Statement allows Assume Role privledges to an untrusted account {permitted_account[1]}")
                            non_compliant_principal.append(principal)
            else:
                # Something is different, return the role so it can be put on the import file and evaluated later.
                logger.error(f"AssumeRolePolicyDocument Statement contains an unknown Principal type:\n {{{key}: {value}}}")
                non_compliant_principal.append(principal)
    
    return(non_compliant_principal)
            
def setup_es_client():
    
    region = os.environ['AWS_DEFAULT_REGION']
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)
    
    es = Elasticsearch(
        hosts=[{'host': os.environ['ES_DOMAIN_ENDPOINT'], 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )
    
    return(es)
    
def get_role_data_from_es(index_name):
    
    # ElasticSearch Client
    es = setup_es_client()

    # ElasticSearch query to find the total number of roles within 24 hours.
    # If we don't do this, there is a default results cap so the results returned will be limited.
    query = {
        "track_total_hits": True,
        "size": 0,
        "query": {
            "bool": {
                "must": [
                {
                    "range": {
                        "configurationItemCaptureTime": {
                            "gte": f"now-24h"
                        }
                    }
                }]
            }
        }
    }
    
    # Get total number of hits.
    total_hits = int(json.dumps(es.search(index=index_name, body=query)['hits']['total']))
    
    query = {
        "size": total_hits,
        "query": {
            "bool": {
                "must": [
                {
                    "range": {
                        "configurationItemCaptureTime": {
                            "gte": f"now-24h"
                        }
                    }
                }]
            }
        }
    }

    data = es.search(index=index_name, body=query)
    
    output = {}

    logger.debug(f"found {total_hits} records")

    for hit in data['hits']['hits']:
        logger.debug(json.dumps(hit, sort_keys=True, default=str, indent=2))
        doc = hit['_source']

        if doc['awsAccountId'] not in output:
            output[doc['awsAccountId']] = []
        
        output[doc['awsAccountId']].append(doc)
    
    return(output)
    

def get_endpoint(domain):
    ''' using the boto3 api, gets the URL endpoint for the cluster '''
    es_client = boto3.client('es')

    response = es_client.describe_elasticsearch_domain(DomainName=domain)
    if 'DomainStatus' in response:
        if 'Endpoint' in response['DomainStatus']:
            return(response['DomainStatus']['Endpoint'])

    logger.error("Unable to get ES Endpoint for {}".format(domain))
    return(None)
