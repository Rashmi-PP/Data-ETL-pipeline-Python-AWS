#!/usr/bin/env python
# coding: utf-8

# In[70]:


import boto3
import botocore
import pandas as pd
import os
import sys
import shutil
import json
import logging
import psycopg2 #to connect to postgresql DB
from zipfile import ZipFile # importing the zipfile module
from sqlalchemy import create_engine
from botocore.exceptions import ClientError


# In[71]:


bucket_name = 'chocolatebucketpp'
object_key = 'abc.zip'
destination_name = 'chocolate_data.zip'
extraction_path = 'extracted_files'
extracted_filename = "flavors_of_cacao.csv"
tablename = 'table1'
secret_name = "postgres-connection"
region_name = "us-east-1"


# In[72]:


# Download file from S3 bucket using boto3
def downloadFromS3(buck_name, obj_key, dest_name):
    s3 = boto3.client('s3')
    try:
        s3.download_file(buck_name, obj_key, dest_name)
    except botocore.exceptions.ClientError as error:
        print("No file to download!!!")    
        return False
    msg = 'downloadFromS3 '+ buck_name + obj_key + dest_name
    logger('DEBUG', msg)
    return True

# Unzip the downloaded object from S3
def unZip(input_filepath, output_filepath):
    # loading the temp.zip and creating a zip object
    with ZipFile(input_filepath, 'r') as zObject:
        # Extracting all the members of the zip
        # into a specific location.
        zObject.extractall(path=output_filepath)
    msg = 'unZipped file'
    logger('DEBUG', msg)
    
#Read the csv file and remove newline from column headers
def chocolateDF(csv_filepath):
    chocolate_df = pd.read_csv(csv_filepath)
    chocolate_df.columns = [x.replace("\n", " ") for x in chocolate_df.columns.to_list()]
    msg = 'csv read done moving to cleaning...'
    logger('DEBUG', msg)
    return chocolate_df

# Data cleaning - change percent from object datatype to float
def clean(input_dataframe):
    input_dataframe['Cocoa Percent'] = input_dataframe['Cocoa Percent'].map(lambda x: x.rstrip('%'))
    input_dataframe['Cocoa Percent'] = input_dataframe['Cocoa Percent'].astype('float')
    msg = 'clean dataframe yaay!'
    logger('DEBUG', msg)
    return input_dataframe


#Pushing table to Postgres DB 
def push_df2db(username, password, hostname, port, database, tablename, dataframe):
    engine = create_engine('postgresql://'+username+':'+password+'@'+hostname+':'+port+'/'+database)
    conn = engine.connect()
    dataframe.to_sql(tablename, engine, if_exists='replace')
    logger('DEBUG', 'pushed data to postgres DB')
    conn.close()
    engine.dispose()
    logger('DEBUG', 'connection to DB closed')

# Delete S3 object after pushing it to database
def delete_bucketobj(buck_name, obj_key):
    s3 = boto3.client('s3')
    s3.delete_object(Bucket=buck_name, Key=obj_key)
    logger('DEBUG', 'deleted s3 obj')
    
#Delete downloaded and extracted files
def removeFiles(dest_name):
    os.remove(dest_name)
    logger('DEBUG', 'removed zip file')
 
#Delete folders created
def removeFolder(extract_path):
    shutil.rmtree(extract_path)
    logger('DEBUG', 'removed folder')

# Populate secret variables
def populate_secrets():
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)['SecretString']
        get_secret_value_response = json.loads(get_secret_value_response)
        
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secrets_dictionary = {
        'username' : get_secret_value_response['username'],
        'password' : get_secret_value_response['password'],
        'hostname' : get_secret_value_response['hostname'],
        'port' : get_secret_value_response['port'],
        'database' : get_secret_value_response['database']
    }
    return secrets_dictionary

def logger(log_level, msg):
    logging.basicConfig(filename = 'logfile.log', encoding = 'utf-8', level=logging.DEBUG)
    if log_level == 'DEBUG':
        logging.debug(msg)


# In[73]:


secrets_dict = populate_secrets()
if downloadFromS3(bucket_name, object_key, destination_name):
    # Starting the pipeline
    unZip(destination_name, extraction_path)
    choco_df = chocolateDF(extraction_path+"/"+extracted_filename)
    choco_df = clean(choco_df)
    push_df2db(secrets_dict['username'], secrets_dict['password'], secrets_dict['hostname'],
               secrets_dict['port'], secrets_dict['database'], tablename, choco_df)
    delete_bucketobj(bucket_name, object_key)
    removeFiles(destination_name)
    removeFolder(extraction_path)

