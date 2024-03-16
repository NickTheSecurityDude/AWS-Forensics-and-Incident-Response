import json, boto3, time, datetime, logging


def lambda_handler(event, context):
    # Set to 1 to revoke current role sessions, this will disrupt other instances using
    # the role until they are restarted or request new temporary credentials.
    REVOKE_CURRENT_SESSIONS = 1

    ec2_client = boto3.client('ec2')
    ssm_client = boto3.client('ssm')
    iam_client = boto3.client('iam')
    s3_client = boto3.client('s3')

    #log_level = "DEBUG"
    log_level = "INFO"
    logging.getLogger(__name__).setLevel(log_level)
    logger = logging.getLogger(__name__)

    logger.debug(event)

    # Get Instance Id From Event
    # Note: this only checks for Inspector, additional ProductNames should be added
    logger.info("Get Instance ID")
    if event['detail']['findings'][0]['ProductName'] == 'Inspector':
        instance_id = event['detail']['findings'][0]['Resources'][0]['Id'].split("/")[1]
        logger.info(instance_id)
    else:
        logger.error("Instance Id Not Found.")
        return 0

    # Get EC2 VPC Id
    vpc_id = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['VpcId']
    logger.debug(vpc_id)

    # Get Instance Type (used to find ram size)
    # instance_type = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['InstanceType']
    # logger.debug(instance_type)

    # Get Instance Role
    logger.info("Get Instance Role")
    instance_profile = \
    ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['IamInstanceProfile'][
        'Arn'].split("/")[1]
    logger.debug(instance_profile)
    instance_role = \
    iam_client.get_instance_profile(InstanceProfileName=instance_profile)['InstanceProfile']['Roles'][0]['RoleName']
    logger.info(instance_role)

    # Get Instance Instance Profile Association Id
    association_id = ec2_client.describe_iam_instance_profile_associations(
        Filters=[{'Name': 'instance-id', 'Values': [instance_id]}]
    )['IamInstanceProfileAssociations'][0]['AssociationId']
    logger.debug(association_id)

    # Get Parameters
    quarantine_sg = \
    ssm_client.get_parameter(Name='/resources/securitygroups/' + vpc_id + '/QuarantineSecurityGroupVPC1/GroupId')[
        'Parameter']['Value']
    quarantine_instance_profile = \
    ssm_client.get_parameter(Name='/resources/iam/instance-profiles/QuarantineRoleInstanceProfile/Arn')['Parameter'][
        'Value']
    forensic_scripts_bucket = ssm_client.get_parameter(Name='/resources/s3/ForensicsScriptsBucket/Name')['Parameter'][
        'Value']
    forensic_data_bucket = ssm_client.get_parameter(Name='/resources/s3/ForensicsDataBucket/Name')['Parameter']['Value']

    # Tag instance
    logger.info("Tag Instance")
    response = ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            {
                'Key': 'Quarantine',
                'Value': 'true'
            },
        ]
    )

    # Detach from ASG (if applicable)
    # Warning this will launch a new instance with the same vulnerability
    # Not applicable in this demo

    # Attach quarantine security group
    logger.info("Add Quarantine Security Group to Instance")
    response = ec2_client.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg]
    )
    logger.debug(response)

    # Attach quarantine role
    # Note: This will not work if the instance is stopped already
    logger.info("Replace Instance Profile with Quarantine Role")
    response = ec2_client.replace_iam_instance_profile_association(
        IamInstanceProfile={
            'Arn': quarantine_instance_profile
        },
        AssociationId=association_id
    )
    logger.debug(response)

    # Policy to revoke old sessions
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    logger.info(iso8601Time)
    deny_older_sessions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["*"],
                "Resource": ["*"],
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": iso8601Time
                    }
                }
            }
        ]
    }

    # Invalidate sessions of original role
    # Other instances currently using this role may need to be stopped and restarted to receive fresh credentials
    if REVOKE_CURRENT_SESSIONS:
        logger.info("Revoking Old Role Sessions")
        response = iam_client.put_role_policy(
            RoleName=instance_role,
            PolicyName='RevokeOlderSessions',
            PolicyDocument=str(json.dumps(deny_older_sessions_policy))
        )
        logger.debug(response)

    # Pause for Instance Profile to be Attached
    logger.info("Pause for 1 minute for Instance Profile to Attach")
    time.sleep(60)

    # Download and run forensic script
    logger.info("Collect Forensic Data from Instance")
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [
            "mkdir /root/forensics || true",
            "cd /root/forensics",
            "aws s3 cp s3://" + forensic_scripts_bucket + "/get-forensic-data.sh ./",
            "chmod 700 get-forensic-data.sh",
            "./get-forensic-data.sh"
        ]}
    )
    logger.debug(response)
    command_id = response['Command']['CommandId']
    logger.debug(command_id)
    sleep = 30
    timeout = 600
    time.sleep(sleep)
    elapsed_time = sleep
    status = "InProgress"
    # Wait for run command to finish
    while elapsed_time < timeout and status == "InProgress":
        logger.info("InProgress and Timeout Not Reached.")
        output = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        status = output['Status']
        elapsed_time += sleep
        time.sleep(sleep)
    logger.debug(output)

    if elapsed_time >= timeout:
        logger.error("Fatal Error: Run Command Timed Out.")
        return 999
    else:
        logger.info("Run Command Finished.")

    # Get objects to enable legalhold object lock in s3
    logger.info("Enable legal hold for forensic data uploaded to S3")
    response = s3_client.list_objects_v2(
        Bucket=forensic_data_bucket,
        Prefix=instance_id
    )

    keys = response['Contents']

    # Check the data was uploaded
    if len(keys) == 0:
        logger.error("Fatal Error: No forensic data files found in S3.")
        return 999

    # Enable legal hold
    for key in keys:
        file_name = key['Key']
        logger.debug(file_name)
        response = s3_client.put_object_legal_hold(
            Bucket=forensic_data_bucket,
            Key=file_name,
            LegalHold={'Status': 'ON'}
        )
        logger.debug(response)

    # Power down instance
    logger.info("Powering Down Instance")
    response = ec2_client.stop_instances(InstanceIds=[instance_id])
    # Wait for power off
    time.sleep(60)
    response = ec2_client.describe_instances(InstanceIds=[instance_id])

    # check if instance is stopped, if not force shutdown
    instance_state = response['Reservations'][0]['Instances'][0]['State']['Name']
    if instance_state != "stopped":
        logger.info("Force Stop Instance")
        response = ec2_client.stop_instances(InstanceIds=[instance_id], Force=True)
        time.sleep(60)

    # Create an ami (snapshot)
    logger.info("Create an AMI of Instance")

    # Global Tags (for AMI and Snapshot)
    ami_global_tags = [
        {
            'Key': 'InstanceId',
            'Value': instance_id
        },
        {
            'Key': 'Timestamp',
            'Value': iso8601Time
        },
        {
            'Key': 'Quarantine',
            'Value': 'true'
        },
        {
            'Key': 'Type',
            'Value': 'ForensicImage'
        }]

    # AMI Tags
    ami_tags = [{
        'Key': 'Name',
        'Value': 'FORENSIC-IMAGE - Compromised EC2 - ' + instance_id
    }]
    ami_tags.extend(ami_global_tags)

    # Snapshot Tags
    snapshot_tags = [{
        'Key': 'Name',
        'Value': 'FORENSIC-SNAPSHOT - Compromised EC2 - ' + instance_id
    }]
    snapshot_tags.extend(ami_global_tags)

    logger.info("Create AMI")
    ami_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).strftime("%Y-%m-%d-%H-%M-%S%Z")
    response = ec2_client.create_image(
        Description='This AMI was created by Lambda, via SecurityHub, and contains the image of an instance suspected of being compromised. ' + instance_id + ' ' + iso8601Time,
        InstanceId=instance_id,
        Name='FORENSIC-IMAGE - ' + instance_id + ' - ' + ami_time,
        TagSpecifications=[
            {
                'ResourceType': 'image',
                'Tags': ami_tags
            },
            {
                'ResourceType': 'snapshot',
                'Tags': snapshot_tags
            }
        ]
    )
    logger.info("Script Completed: Forensinc data collected.")
    logger.info("Allow extra time for the AMI to complete.")

    return 1
