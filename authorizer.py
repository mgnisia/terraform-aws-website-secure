import json
import boto3
import base64
from botocore.exceptions import ClientError

region_name = '${data.aws_region.current.name}'

# Create a Secrets Manager client
session = boto3.session.Session()
client = session.client(
    service_name='secretsmanager',
    region_name=region_name
)

def lambda_handler(event, context):
    secretName = 'OriginVerifySecret'
    secretValue=''
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secretName)
        get_pending_secret_value_response = ""
        try: 
            get_pending_secret_value_response = client.get_secret_value(SecretId=secretName,VersionStage='AWSPENDING')
        except ClientError as e:
            print (e.response["Error"]["Code"])
        
        secret_HeaderValue = json.loads(get_secret_value_response['SecretString'])['HEADERVALUE']
        if get_pending_secret_value_response:
            pending_secret_HeaderValue = json.loads(get_pending_secret_value_response['SecretString'])['HEADERVALUE']
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            #default
            raise e
    response={
        "isAuthorized":False
    }
    if (event['headers']['x-origin-verify'] == secret_HeaderValue or event['headers']['x-origin-verify'] == pending_secret_HeaderValue):
        response={
            "isAuthorized":True
        }
    print (response)
    return response