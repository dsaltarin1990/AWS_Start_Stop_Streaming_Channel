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

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/your-repo.git
   cd your-repo
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

5. Prepare your channel configuration file `Channels.json`. For security reasons, do not commit your real `Channels.json` file. Use `Channels.example.json` as a template.

## Usage

Run the script with the required channel argument:

```bash
python Example_Boto3_Start_AWS_Channel.py --channel Channel1
```

Additional options:

- `--config`: Path to the channel configuration JSON file (default: `./Channels.json`)
- `--skip-subnet-check`: Skip checking IP availability in subnets
- `--env-file`: Custom path to `.env` file

Example:

```bash
python Example_Boto3_Start_AWS_Channel.py --channel Channel1 --skip-subnet-check
```

## Logging

Logs are saved to `channel_operations.log`. Make sure this file is ignored in `.gitignore`.

## Security Notes

- Never commit your `.env` file or any file containing secrets to the repository.
- Mask or exclude any sensitive identifiers from configuration files before sharing.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
