# AWS_Start_Stop_Streaming_Channel
This project is a Python script to start AWS MediaLive channels, MediaConnect flows, and Conductor channels via API. It leverages AWS SDK (boto3) and custom authentication to manage streaming channel workflows.

## Features

- Start MediaLive channels by Channel ID
- Start MediaConnect flows by Flow ARN
- Start Conductor channels via authenticated API calls
- Check subnet IP availability before starting channels
- Environment configuration via `.env` file
- Logging of operations and errors

## Requirements

- Python 3.6+
- `boto3` library
- `requests` library
- `python-dotenv` library
- https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
- https://docs.aws.amazon.com/elemental-cl3/latest/apireference/hashing-api-key.html

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/repo.git
   cd repo
   ```

2. Create a virtual environment and activate it (optional but recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root with the following variables:

   ```
   AWS_ACCESS_KEY_ID=your_aws_access_key_id
   AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
   AWS_SESSION_TOKEN=optional_session_token
   api_key=your_api_key
   x_auth_user=your_auth_user
   api_url_start=https://your.api.endpoint/start
   ```

## Usage

Run the script with the required channel argument:

```bash
python Example_Boto3_Start_AWS_Channel.py --channel Channel1
```

Additional options:

- `--config`: Path to the channel configuration JSON file (default: `./Channels.json`)
- `--skip-subnet-check`: Skip checking IP availability in subnets

Example:

```bash
python Example_Boto3_Start_AWS_Channel.py --channel Channel1 --skip-subnet-check
```

## Logging

Logs are saved to `channel_operations.log`.
