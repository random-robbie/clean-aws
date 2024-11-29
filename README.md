# AWS Resource Cleanup Tool

A Python script to clean up AWS resources across all regions. This tool is useful for removing test resources, cleaning up after experiments, or general AWS account maintenance.

I made it due to costs and not knowing where the hell they were coming from and i did not care what was in my account.

## Features

This tool automatically cleans up the following AWS resources:

### Global Resources
- S3 Buckets:
  - Removes bucket policies
  - Removes public access blocks
  - Deletes all objects (including versioned objects)
  - Removes encryption settings
  - Deletes lifecycle rules
  - Deletes the buckets themselves

### Regional Resources
Cleans up these resources in all enabled AWS regions:

- Lambda Resources:
  - Functions
  - Layers (all versions)
  - Event source mappings

- EC2 Resources:
  - Running instances
  - EBS volumes
  - Security groups (except default)
  - Key pairs

- Elastic Beanstalk:
  - Environments
  - Applications
  - Related resources

- ECR (Elastic Container Registry):
  - Repositories
  - Container images

- CloudWatch Logs:
  - Log groups
  - Log streams
  - Retention policies

## Prerequisites

- Python 3.x
- Boto3 library
- AWS credentials configured with appropriate permissions
- AWS CLI profile set up

## Installation

1. Clone this repository:
```bash
git clone https://github.com/random-robbie/clean-aws.git
cd clean-aws
```

2. Install required packages:
```bash
pip install boto3
```

3. Ensure your AWS credentials are configured:
```bash
aws configure --profile default
```

## Usage

1. Review and modify the AWS_PROFILE variable in the script if needed:
```python
AWS_PROFILE = "default"  # Change this to your AWS profile name
```

2. Run the script:
```bash
python3 cleanup.py
```

## Safety Features

The script includes several safety measures:

- Only operates in enabled regions for your account
- Shows which AWS identity it's operating as
- Preserves default VPC security groups
- Includes error handling and logging
- Waits for resource deletion before proceeding

## Important Notes

⚠️ **WARNING**: This script will delete resources permanently. Use with caution!

- The script will attempt to delete ALL resources of the supported types
- There is no "dry run" mode - all deletions are permanent
- Make sure you have the correct AWS permissions
- Consider running in a test account first
- Review the code before running in production environments

## Error Handling

- The script handles various AWS errors gracefully
- It will continue even if some deletions fail
- All errors are logged to the console
- Failed deletions are reported but don't stop the script

## Limitations

- Does not handle all AWS resource types
- Some resources might require manual cleanup
- Resource deletion might fail due to dependencies
- Some resources might require additional permissions

## Contributing

Contributions are welcome! Please feel free to submit pull requests with improvements.

## License

[License Type] - see LICENSE file for details

## Disclaimer

This tool is provided as-is. Always review and test the code before running it in your environment. The authors are not responsible for any unintended resource deletion or associated costs.
