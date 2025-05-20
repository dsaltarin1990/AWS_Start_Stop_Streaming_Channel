#!/usr/bin/python3

import argparse
import os
import requests
import boto3
import logging
import json
import urllib3
from urllib.parse import urlparse
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from dotenv import load_dotenv
from auth_util import get_timestamp_and_expires, get_relative_url, calculate_md5_hash, prepare_headers


class ChannelManager:
    def __init__(self, env_path, channels_file_path):
        # Configure logging
        self._setup_logging()
        
        # Load environment variables
        self._load_environment(env_path)
        
        # Load channel configuration
        self.channels = self._load_channels_config(channels_file_path)
        
        # Initialize AWS clients
        self.region = 'eu-west-XX'  
        self._init_aws_clients()

    def _setup_logging(self):
        """Configure the logging system."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("channel_operations.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_environment(self, env_path):
        """Load environment variables from the specified .env file."""
        if not os.path.exists(env_path):
            self.logger.error(f".env file not found: {env_path}")
            raise FileNotFoundError(f".env file not found: {env_path}")
            
        load_dotenv(dotenv_path=env_path)
        
        # Verify that required environment variables are present
        required_vars = [
            'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 
            'api_key', 'x_auth_user', 'api_url_stop'
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            self.logger.error(f"Missing environment variables: {', '.join(missing_vars)}")
            raise EnvironmentError(f"Missing environment variables: {', '.join(missing_vars)}")

    def _load_channels_config(self, file_path):
        """Load channel configuration from the specified JSON file."""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Error loading configuration file: {e}")
            raise

    def _init_aws_clients(self):
        """Initialize AWS clients."""
        session = boto3.Session(
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=self.region
        )
        
        self.mediaconnect_client = session.client('mediaconnect')
        self.medialive_client = session.client('medialive')

    def stop_mediaconnect_flow(self, flow_arn):
        """Stop a MediaConnect flow."""
        try:
            self.mediaconnect_client.stop_flow(FlowArn=flow_arn)
            self.logger.info(f'Stopped MediaConnect flow {flow_arn}')
            return True
        except ClientError as e:
            self.logger.error(f"Error stopping MediaConnect flow {flow_arn}: {e}")
            return False

    def stop_medialive_channel(self, channel_id):
        """Stop a MediaLive channel."""
        try:
            self.medialive_client.stop_channel(ChannelId=channel_id)
            self.logger.info(f'Stopped MediaLive channel {channel_id}')
            return True
        except ClientError as e:
            self.logger.error(f"Error stopping MediaLive channel {channel_id}: {e}")
            return False

    def stop_conductor_channel(self, conductor_channel_id):
        """Stop a Conductor channel via API."""
        # Prepare authentication
        _, x_auth_expires = get_timestamp_and_expires()
        relative_url = get_relative_url(os.getenv('api_url_stop'))
        _, x_auth_key = calculate_md5_hash(
            os.getenv('api_key'), 
            os.getenv('x_auth_user'), 
            relative_url, 
            x_auth_expires
        )
        
        # Prepare headers
        headers = prepare_headers(
            os.getenv('x_auth_user'), 
            x_auth_expires, 
            x_auth_key
        )
        
        # Prepare request body
        xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
        <channel_ids type="array">
            <channel_id>{conductor_channel_id}</channel_id>
        </channel_ids>'''
        
        # Disable SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        try:
            # Send request
            response = requests.post(
                os.getenv('api_url_stop'), 
                headers=headers, 
                data=xml_body, 
                verify=False, 
                timeout=10
            )
            
            # Verify response
            response.raise_for_status()
            self.logger.info(f"Conductor channel {conductor_channel_id} stopped successfully: {response.status_code}")
            return True
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error stopping Conductor channel {conductor_channel_id}: {e}")
            if hasattr(e, 'response') and e.response:
                self.logger.error(f"Status code: {e.response.status_code}, Response: {e.response.text}")
            return False

    def stop_channel(self, channel_name):
        """Stop a specific channel."""
        # Verify that the channel exists in the configuration
        if channel_name not in self.channels:
            self.logger.error(f"Channel {channel_name} is not defined in the configuration.")
            return False
        
        channel_config = self.channels[channel_name]
        self.logger.info(f"Stopping channel {channel_name}...")
        
        # Stop Conductor channel
        conductor_success = self.stop_conductor_channel(channel_config["conductor_channel_id"])
        
        # Stop MediaConnect flows
        mediaconnect_success = all(
            self.stop_mediaconnect_flow(flow_arn) 
            for flow_arn in channel_config.get('mediaconnect_flows', [])
        )
        
        # Stop MediaLive channel
        medialive_success = True
        if 'medialive_id' in channel_config:
            medialive_success = self.stop_medialive_channel(channel_config['medialive_id'])
        
        # Evaluate overall success
        if conductor_success and mediaconnect_success and medialive_success:
            self.logger.info(f"CHANNEL NAME: {channel_name} STOPPED SUCCESSFULLY")
            return True
        else:
            self.logger.warning(f"Channel {channel_name} stop completed with errors.")
            return False


def main():
    # Configure argument parser
    parser = argparse.ArgumentParser(description="Stop a specific channel")
    parser.add_argument('--channel', type=str, required=True, 
                        help='Channel to stop (e.g., Channel1, Channel2, etc)')
    args = parser.parse_args()
    
    # Configuration file paths
    env_path = ".../envpathtofill"
    channels_file_path = './Channels_example.json'
    
    try:
        # Initialize the channel manager
        channel_manager = ChannelManager(env_path, channels_file_path)
        
        # Stop the specified channel
        success = channel_manager.stop_channel(args.channel)
        
        # Exit with appropriate code
        exit(0 if success else 1)
    except Exception as e:
        logging.error(f"Error during script execution: {e}")
        exit(1)


if __name__ == "__main__":
    main()