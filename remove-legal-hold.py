import boto3,sys

# Use this script remove the legal hold so you can delete them

try:
  bucket_name=sys.argv[1]
except:
  print("Usage: python remove-legal-hold.py <bucket_name>")
  sys.exit(1)

s3_client = boto3.client('s3')

response = s3_client.list_objects_v2(
  Bucket=bucket_name,
)

keys = response['Contents']

# Disable legal hold
for key in keys:
  file_name = key['Key']
  print(file_name)
  response = s3_client.put_object_legal_hold(
    Bucket=bucket_name,
    Key=file_name,
    LegalHold={'Status': 'OFF'}
  )
  print(response)