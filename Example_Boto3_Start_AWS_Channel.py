#!/bin/python3

import argparse
import os
import requests
import boto3
import logging
import json
import ipaddress
import sys
import urllib3
from urllib.parse import urlparse
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from dotenv import load_dotenv
from auth_util import get_timestamp_and_expires, get_relative_url, calculate_md5_hash, prepare_headers

# Logging configuration
def setup_logging():
    """Configure the logging system."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('channel_operations.log')
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

def load_environment(env_path=None):
    """Load environment variables from the specified .env file."""
    if env_path is None:
        env_path = ".../envpathtofill"
    
    if not os.path.exists(env_path):
        logger.error(f"File .env not found: {env_path}")
        sys.exit(1)
    
    load_dotenv(dotenv_path=env_path)
    
    # Verify essential environment variables
    required_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'api_key', 'x_auth_user', 'api_url_start']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
    
    logger.info("Environment variables loaded successfully")

def load_channels_from_file(file_path):
    """Load channel configuration from JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Error parsing JSON file: {file_path}")
        sys.exit(1)

def create_aws_client(service, region='eu-west-XXX'):
    """Create an AWS client for the specified service."""
    try:
        return boto3.client(
            service,
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=region
        )
    except (NoCredentialsError, PartialCredentialsError) as e:
        logger.error(f"AWS authentication error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error creating {service} client: {e}")
        sys.exit(1)

def start_mediaconnect_flow(flow_arn):
    """Start a MediaConnect flow."""
    mediaconnect_client = create_aws_client('mediaconnect')
    
    try:
        response = mediaconnect_client.start_flow(FlowArn=flow_arn)
        logger.info(f'Started MediaConnect flow: {flow_arn}')
        return True
    except ClientError as e:
        error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
        if error_code == 'ResourceInUseException':
            logger.warning(f"MediaConnect flow {flow_arn} is already running")
            return True
        logger.error(f"Error starting MediaConnect flow {flow_arn}: {e}")
        return False

def start_medialive_channel(channel_id):
    """Start a MediaLive channel."""
    medialive_client = create_aws_client('medialive')
    
    try:
        response = medialive_client.start_channel(ChannelId=channel_id)
        logger.info(f'Started MediaLive channel: {channel_id}')
        return True
    except ClientError as e:
        error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
        error_message = getattr(e, 'response', {}).get('Error', {}).get('Message', '')
        if error_code == 'BadRequestException' and 'not in IDLE state' in error_message:
            logger.warning(f"MediaLive channel {channel_id} is not in IDLE state. It might already be running")
            return True
        logger.error(f'Error starting MediaLive channel {channel_id}: {e}')
        return False

def check_subnet_ip_availability(threshold=10, exit_on_error=False):
    """Check IP availability in the specified subnets."""
    ec2_client = create_aws_client('ec2')
    
    subnet_ids = [
        'subnet-1',  # dr-aws-subnet-1
        'subnet-2',  # dr-aws-subnet-2 
        'subnet-3',  # dr-aws-subnet-3
    ]
    
    has_warnings = False
    
    for subnet_id in subnet_ids:
        try:
            response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
            subnet = response['Subnets'][0]
            cidr_block = subnet['CidrBlock']
            total_ips = ipaddress.IPv4Network(cidr_block).num_addresses
            reserved_ips = 5  # AWS reserves 5 IPs in each subnet
            available_ips = subnet['AvailableIpAddressCount']
            used_ips = total_ips - reserved_ips - available_ips
            
            logger.info(f"Subnet {subnet_id}: CIDR {cidr_block}, Available IPs: {available_ips}, Used IPs: {used_ips}")
            
            if available_ips < threshold:
                warning = (f"WARNING: Available IPs below threshold ({threshold}) in subnet {subnet_id}! "
                          f"Available: {available_ips}, Total: {total_ips - reserved_ips}")
                logger.warning(warning)
                has_warnings = True
                
                if exit_on_error:
                    sys.exit(f"Forced exit due to low IP availability in subnet {subnet_id}")
        except ClientError as e:
            logger.error(f"Error checking subnet {subnet_id}: {e}")
    
    logger.info('Subnet check completed')
    return not has_warnings

def start_conductor_channel(conductor_channel_id):
    """Start the Conductor channel via API."""
    # Disable SSL warnings (for this client only)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        api_key = os.getenv('api_key')
        x_auth_user = os.getenv('x_auth_user')
        api_url_start = os.getenv('api_url_start')
        
        # Prepare authentication
        _, x_auth_expires = get_timestamp_and_expires()
        relative_url = get_relative_url(api_url_start)
        _, x_auth_key = calculate_md5_hash(api_key, x_auth_user, relative_url, x_auth_expires)
        headers = prepare_headers(x_auth_user, x_auth_expires, x_auth_key)
        
        # Prepare request body
        xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<channel_ids type="array">
    <channel_id>{conductor_channel_id}</channel_id>
</channel_ids>'''
        
        logger.info(f"Starting Conductor channel ID: {conductor_channel_id}")
        response = requests.post(api_url_start, headers=headers, data=xml_body, verify=False, timeout=15)
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"Conductor channel started successfully. Code: {response.status_code}")
            return True
        else:
            logger.error(f"Error starting Conductor channel. Code: {response.status_code}, Response: {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"Error in Conductor API request: {e}")
        return False

def main():
    """Main program function."""
    # Argument parser
    parser = argparse.ArgumentParser(description="Start a specific channel")
    parser.add_argument('--channel', type=str, required=True, 
                      help='Channel to start (e.g. Channel1, Channel2, etc)')
    parser.add_argument('--config', type=str, default='./Channels_example.json',
                      help='Path to channel configuration file (default: ./Channels_example.json)')
    parser.add_argument('--skip-subnet-check', action='store_true',
                      help='Skip checking IP availability in subnets')
    parser.add_argument('--env-file', type=str, 
                      help='Custom path to .env file')
    
    args = parser.parse_args()
    
    # Load environment
    load_environment(args.env_file)
    
    # Load channel configuration
    channels = load_channels_from_file(args.config)
    
    # Check if channel exists
    selected_channel = channels.get(args.channel)
    if not selected_channel:
        logger.error(f"Channel '{args.channel}' is not defined")
        sys.exit(1)
    
    logger.info(f"===== STARTING CHANNEL: {args.channel} =====")
    
    # Check that all required keys are present
    required_keys = ['conductor_channel_id', 'medialive_id', 'mediaconnect_flows']
    missing_keys = [key for key in required_keys if key not in selected_channel]
    if missing_keys:
        logger.error(f"Incomplete configuration for channel {args.channel}. Missing fields: {', '.join(missing_keys)}")
        sys.exit(1)
    
    # Check subnet IP availability unless explicitly skipped
    if not args.skip_subnet_check:
        subnet_ok = check_subnet_ip_availability(threshold=10, exit_on_error=False)
        if not subnet_ok:
            logger.warning("Proceeding despite warnings about IP availability in subnets")
    else:
        logger.info("Subnet check skipped as requested")
    
    # Start Conductor channel
    conductor_success = start_conductor_channel(selected_channel['conductor_channel_id'])
    if not conductor_success:
        logger.error("Unable to start Conductor channel. Process aborted.")
        sys.exit(1)
    
    # Start MediaConnect flows
    flow_success = True
    for flow_arn in selected_channel['mediaconnect_flows']:
        if not start_mediaconnect_flow(flow_arn):
            logger.error(f"Error starting MediaConnect flow: {flow_arn}")
            flow_success = False
    
    if not flow_success:
        logger.warning("One or more MediaConnect flows did not start correctly")
    
    # Start MediaLive channel
    medialive_success = start_medialive_channel(selected_channel['medialive_id'])
    if not medialive_success:
        logger.error("Error starting MediaLive channel")
        sys.exit(1)
    
    logger.info(f"===== CHANNEL {args.channel} STARTED SUCCESSFULLY =====")

if __name__ == "__main__":
    main()