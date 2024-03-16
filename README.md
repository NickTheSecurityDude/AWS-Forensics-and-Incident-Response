# AWS-Forensics-and-Incident-Response Automation

These resources will respond to a SecurityHub finding by quarantining and affected EC2 Instance and collecting forensic data from it.

## Installation Steps
1. Enable Inspector and Security Hub
2. Create a Custom Action in SecurityHub as follows:
   1. Action name: CompromisedEC2
   2. Description: Trigger a Lambda Incident Response function to quarantine an instnace and collect forensic data.
   3. Custom action ID: CompromisedEC2
3. Create an EC2 instance (if needed)
4. Create an S3 bucket and upload the file: aws_forensics_lambda.zip to the root folder
5. Create a CloudFormation stack called forensics-and-incident-response, using the file: aws_forensics.yaml
6. Upload the file called get-forensic-data.sh to the bucket starting with:
   forensics-and-incident-resp-forensicsscriptsbucket-\<random-string\>   
   **Note: there are 2 similarly named buckets, be sure to upload to the one with "scripts" in the name**
7. In SecurityHub, look for a finding for an EC2 instance, click it, and select Actions-->CompromisedEC2
    Note: you will need to wait for some findings to appear, or upload a file which will trigger an inspector rule
8. Wait a few minutes for the lambda script to run, then verify the following:
    1. The security group what changes
    2. The role was changed
    3. Check that Older sessions were revoked for the old role
    4. Within the S3 Forensic Data bucket, a folder with the name of the instance ID contains the foresnsic data
    5. An AMI was created and tagged
    6. The instance was powered off
