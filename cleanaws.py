#!/usr/bin/env python3
import boto3
import time
from botocore.exceptions import ClientError

AWS_PROFILE = "default"

def get_all_regions(session):
    try:
        # First try to get enabled regions for the account
        sts = session.client('sts')
        current_identity = sts.get_caller_identity()
        print(f"Operating as: {current_identity['Arn']}")

        ec2 = session.client('ec2', region_name='us-east-1')
        regions = []
        
        # Try to describe regions with region opt-in check
        response = ec2.describe_regions(AllRegions=False)  # Only get opted-in regions
        regions = [region['RegionName'] for region in response['Regions']]
        
        print(f"Found {len(regions)} enabled regions")
        return regions
    except Exception as e:
        print(f"Error getting regions: {str(e)}")
        # Return commonly used regions as fallback
        default_regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 
                         'eu-west-1', 'eu-west-2', 'ap-southeast-1', 'ap-southeast-2']
        print(f"Falling back to default regions: {default_regions}")
        return default_regions

def delete_lambda_resources(session, region):
    print(f"\nCleaning up Lambda resources in {region}...")
    lambda_client = session.client('lambda', region_name=region)
    
    try:
        # Delete Lambda functions
        print("Looking for Lambda functions...")
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                try:
                    print(f"Deleting function: {function_name}")
                    lambda_client.delete_function(FunctionName=function_name)
                except Exception as e:
                    print(f"Error deleting function {function_name}: {str(e)}")

        # Delete Lambda layers
        print("Looking for Lambda layers...")
        paginator = lambda_client.get_paginator('list_layers')
        for page in paginator.paginate():
            for layer in page['Layers']:
                layer_name = layer['LayerName']
                try:
                    # Get all versions of the layer
                    versions_paginator = lambda_client.get_paginator('list_layer_versions')
                    for versions_page in versions_paginator.paginate(LayerName=layer_name):
                        for version in versions_page['LayerVersions']:
                            version_number = version['Version']
                            print(f"Deleting layer {layer_name} version {version_number}")
                            lambda_client.delete_layer_version(
                                LayerName=layer_name,
                                VersionNumber=version_number
                            )
                except Exception as e:
                    print(f"Error deleting layer {layer_name}: {str(e)}")

        # Delete event source mappings
        print("Looking for event source mappings...")
        paginator = lambda_client.get_paginator('list_event_source_mappings')
        for page in paginator.paginate():
            for mapping in page['EventSourceMappings']:
                mapping_uuid = mapping['UUID']
                try:
                    print(f"Deleting event source mapping: {mapping_uuid}")
                    lambda_client.delete_event_source_mapping(UUID=mapping_uuid)
                except Exception as e:
                    print(f"Error deleting event source mapping {mapping_uuid}: {str(e)}")

    except Exception as e:
        print(f"Error in Lambda cleanup for region {region}: {str(e)}")

def delete_ec2_resources(session, region):
    print(f"\nCleaning up EC2 resources in {region}...")
    ec2 = session.client('ec2', region_name=region)
    
    try:
        # Terminate EC2 instances
        print("Looking for EC2 instances...")
        instances_response = ec2.describe_instances()
        instance_ids = []
        
        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                state = instance['State']['Name']
                if state not in ['terminated', 'shutting-down']:
                    instance_ids.append(instance_id)
                    print(f"Found running instance: {instance_id}")

        if instance_ids:
            print(f"Terminating instances: {instance_ids}")
            ec2.terminate_instances(InstanceIds=instance_ids)
            
            # Wait for instances to terminate
            print("Waiting for instances to terminate...")
            waiter = ec2.get_waiter('instance_terminated')
            try:
                waiter.wait(InstanceIds=instance_ids)
            except Exception as e:
                print(f"Error waiting for instances to terminate: {str(e)}")

        # Delete EBS volumes
        print("Looking for EBS volumes...")
        volumes_response = ec2.describe_volumes()
        for volume in volumes_response['Volumes']:
            volume_id = volume['VolumeId']
            if volume['State'] != 'in-use':
                try:
                    print(f"Deleting volume: {volume_id}")
                    ec2.delete_volume(VolumeId=volume_id)
                except Exception as e:
                    print(f"Error deleting volume {volume_id}: {str(e)}")

        # Delete security groups
        print("Looking for security groups...")
        security_groups = ec2.describe_security_groups()['SecurityGroups']
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg['GroupName']
            
            # Skip the default security group
            if group_name == 'default':
                continue
                
            try:
                print(f"Deleting security group: {group_id} ({group_name})")
                ec2.delete_security_group(GroupId=group_id)
            except Exception as e:
                print(f"Error deleting security group {group_id}: {str(e)}")

        # Delete key pairs
        print("Looking for key pairs...")
        key_pairs = ec2.describe_key_pairs()['KeyPairs']
        for key in key_pairs:
            key_name = key['KeyName']
            try:
                print(f"Deleting key pair: {key_name}")
                ec2.delete_key_pair(KeyName=key_name)
            except Exception as e:
                print(f"Error deleting key pair {key_name}: {str(e)}")

    except Exception as e:
        print(f"Error in EC2 cleanup for region {region}: {str(e)}")

def delete_elastic_beanstalk(session, region):
    print(f"\nCleaning up Elastic Beanstalk in {region}...")
    eb = session.client('elasticbeanstalk', region_name=region)
    
    try:
        applications = eb.describe_applications()
        for app in applications['Applications']:
            app_name = app['ApplicationName']
            print(f"Found EB application: {app_name}")
            
            environments = eb.describe_environments(ApplicationName=app_name)
            for env in environments['Environments']:
                env_name = env['EnvironmentName']
                print(f"Terminating environment: {env_name}")
                try:
                    eb.terminate_environment(EnvironmentName=env_name)
                except Exception as e:
                    print(f"Error terminating environment {env_name}: {str(e)}")
            
            print("Waiting for environments to terminate...")
            while True:
                environments = eb.describe_environments(ApplicationName=app_name)
                if not environments['Environments'] or all(env['Status'] == 'Terminated' for env in environments['Environments']):
                    break
                time.sleep(10)
            
            print(f"Deleting application: {app_name}")
            try:
                eb.delete_application(ApplicationName=app_name)
            except Exception as e:
                print(f"Error deleting application {app_name}: {str(e)}")
                
    except Exception as e:
        print(f"Error in Elastic Beanstalk cleanup for region {region}: {str(e)}")

def delete_s3_buckets(session):
    print("\nCleaning up S3 buckets...")
    s3 = session.client('s3')
    
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            print(f"Found bucket: {bucket_name}")
            try:
                # Remove bucket policy first
                try:
                    print(f"Removing bucket policy for: {bucket_name}")
                    s3.delete_bucket_policy(Bucket=bucket_name)
                except Exception as e:
                    print(f"Error removing bucket policy (this is often normal): {str(e)}")

                # Remove bucket public access block
                try:
                    print(f"Removing public access block for: {bucket_name}")
                    s3.delete_public_access_block(Bucket=bucket_name)
                except Exception as e:
                    print(f"Error removing public access block (this is often normal): {str(e)}")

                # Delete bucket lifecycle
                try:
                    print(f"Removing bucket lifecycle for: {bucket_name}")
                    s3.delete_bucket_lifecycle(Bucket=bucket_name)
                except Exception as e:
                    print(f"Error removing bucket lifecycle (this is often normal): {str(e)}")

                # Delete bucket encryption
                try:
                    print(f"Removing bucket encryption for: {bucket_name}")
                    s3.delete_bucket_encryption(Bucket=bucket_name)
                except Exception as e:
                    print(f"Error removing bucket encryption (this is often normal): {str(e)}")

                # Delete all objects including versions
                print(f"Deleting objects from bucket: {bucket_name}")
                paginator = s3.get_paginator('list_object_versions')
                try:
                    for page in paginator.paginate(Bucket=bucket_name):
                        delete_keys = []
                        if 'Versions' in page:
                            delete_keys.extend([{'Key': v['Key'], 'VersionId': v['VersionId']} 
                                            for v in page['Versions']])
                        if 'DeleteMarkers' in page:
                            delete_keys.extend([{'Key': dm['Key'], 'VersionId': dm['VersionId']} 
                                            for dm in page['DeleteMarkers']])
                        if delete_keys:
                            s3.delete_objects(
                                Bucket=bucket_name,
                                Delete={'Objects': delete_keys}
                            )
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucket':
                        continue
                    else:
                        print(f"Error deleting objects: {str(e)}")

                # Final deletion of bucket
                print(f"Attempting to delete bucket: {bucket_name}")
                try:
                    s3.delete_bucket(Bucket=bucket_name)
                    print(f"Successfully deleted bucket: {bucket_name}")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucket':
                        print(f"Bucket {bucket_name} already deleted")
                    else:
                        print(f"Final error deleting bucket {bucket_name}: {str(e)}")
                        
            except Exception as e:
                print(f"Error processing bucket {bucket_name}: {str(e)}")
                    
    except Exception as e:
        print(f"Error in S3 cleanup: {str(e)}")

def delete_ecr_images(session, region):
    print(f"\nCleaning up ECR repositories in {region}...")
    ecr = session.client('ecr', region_name=region)
    
    try:
        repositories = ecr.describe_repositories()['repositories']
        for repo in repositories:
            repo_name = repo['repositoryName']
            print(f"Found repository: {repo_name}")
            
            try:
                paginator = ecr.get_paginator('list_images')
                for page in paginator.paginate(repositoryName=repo_name):
                    if 'imageIds' in page:
                        print(f"Deleting images in repository: {repo_name}")
                        ecr.batch_delete_image(
                            repositoryName=repo_name,
                            imageIds=page['imageIds']
                        )
                
                ecr.delete_repository(repositoryName=repo_name, force=True)
                print(f"Deleted repository: {repo_name}")
            except Exception as e:
                print(f"Error cleaning up repository {repo_name}: {str(e)}")
                
    except Exception as e:
        print(f"Error in ECR cleanup for region {region}: {str(e)}")

def delete_cloudwatch_logs(session, region):
    print(f"\nCleaning up CloudWatch Logs in {region}...")
    logs = session.client('logs', region_name=region)
    
    try:
        # List all log groups
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                log_group_name = log_group['logGroupName']
                try:
                    print(f"Deleting log group: {log_group_name}")
                    
                    # Delete all retention policies first
                    try:
                        logs.delete_retention_policy(logGroupName=log_group_name)
                    except Exception as e:
                        print(f"Error deleting retention policy for {log_group_name}: {str(e)}")
                    
                    # Delete the log group
                    logs.delete_log_group(logGroupName=log_group_name)
                    print(f"Successfully deleted log group: {log_group_name}")
                    
                except Exception as e:
                    print(f"Error deleting log group {log_group_name}: {str(e)}")
    
    except Exception as e:
        print(f"Error in CloudWatch Logs cleanup for region {region}: {str(e)}")

def main():
    print("Starting AWS cleanup across all regions...")
    
    session = boto3.Session(profile_name=AWS_PROFILE)
    regions = get_all_regions(session)
    print(f"Found regions: {regions}")
    
    # S3 is global, so we only need to do this once
    delete_s3_buckets(session)
    
    # Process each region
    for region in regions:
        print(f"\nProcessing region: {region}")
        
        # Add CloudWatch Logs cleanup
        delete_cloudwatch_logs(session, region)
        
        # Delete Lambda resources
        delete_lambda_resources(session, region)
        
        # Delete EC2 resources
        delete_ec2_resources(session, region)
        
        # Delete Elastic Beanstalk applications and environments
        delete_elastic_beanstalk(session, region)
        
        # Delete ECR repositories and images
        delete_ecr_images(session, region)
    
    print("\nCleanup complete across all regions!")

if __name__ == "__main__":
    main()
