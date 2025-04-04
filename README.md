# Vulnerability Scanner with SMS Notifications

This project is a Python-based vulnerability scanner that automates OpenVAS scans and sends SMS notifications when critical vulnerabilities are detected.

## Features

- Automated vulnerability scanning via a command-line interface
- Integration with OpenVAS/GVM (Greenbone Vulnerability Manager)
- Critical findings extraction and categorization based on CVSS scores
- SMS notifications via Twilio API for real-time alerts
- JSON reporting with detailed vulnerability information
- External configuration via YAML file

## Prerequisites

### System Requirements

- Linux system (tested on Ubuntu 20.04/22.04)
- Python 3.8 or higher
- OpenVAS/GVM 20.08 or higher
- Valid Twilio account (for SMS notifications)

### Required Python Packages

```
pip install python-gvm twilio pyyaml
```

## Installation

### 1. Install OpenVAS/GVM

To install OpenVAS/GVM on Ubuntu:

```bash
# Add the PPA
sudo add-apt-repository ppa:mrazavi/gvm
sudo apt update

# Install OpenVAS
sudo apt install gvm

# Run initial setup
sudo gvm-setup

# Start the services
sudo gvm-start
```

### 2. Install Python Dependencies

```bash
pip install python-gvm twilio pyyaml
```

### 3. Clone the Repository

```bash
git clone https://github.com/yourusername/vulnerability-scanner.git
cd vulnerability-scanner
```

### 4. Configure the Application

Copy the example configuration file and modify it to suit your needs:

```bash
cp config.yml.example config.yml
```

Edit `config.yml` with your configuration details:

- GVM socket path (typically `/var/run/gvmd/gvmd.sock`)
- OpenVAS scan configuration IDs
- Twilio credentials for SMS notifications
- Severity threshold for critical vulnerabilities

## Configuration Options

The `config.yml` file contains the following configuration options:

| Parameter | Description |
|-----------|-------------|
| `gvm_socket_path` | Path to the GVM socket file |
| `scan_config_id` | ID of the scan configuration to use |
| `scanner_id` | ID of the scanner to use |
| `port_list_id` | ID of the port list to scan |
| `severity_threshold` | CVSS score threshold for critical vulnerabilities |
| `twilio.account_sid` | Twilio account SID |
| `twilio.auth_token` | Twilio authentication token |
| `twilio.from_number` | Twilio phone number to send SMS from |
| `twilio.to_number` | Recipient phone number for SMS alerts |

### Finding GVM IDs

To find the correct IDs for your GVM installation:

```bash
# For scan configurations
gvm-cli --gmp-username admin --gmp-password your_password socket --xml "<get_configs/>"

# For scanners
gvm-cli --gmp-username admin --gmp-password your_password socket --xml "<get_scanners/>"

# For port lists
gvm-cli --gmp-username admin --gmp-password your_password socket --xml "<get_port_lists/>"
```

## Usage

### Basic Command

```bash
python vuln_scanner.py --target "Company Website" --hosts "example.com" --username "admin" --password "password" --output-dir "./reports"
```

### Command Line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--config` | No | Path to configuration file (default: `./config.yml`) |
| `--target` | Yes | Name of the scan target |
| `--hosts` | Yes | Target hosts (IP, range, or hostname) |
| `--username` | Yes | GVM username |
| `--password` | Yes | GVM password |
| `--output-dir` | No | Output directory for reports (default: `./reports`) |

## Setting Up Cron Jobs

To schedule regular scans using cron:

1. Edit your crontab:
   ```bash
   crontab -e
   ```

2. Add an entry to run daily scans:
   ```
   # Run vulnerability scan daily at 2 AM
   0 2 * * * cd /path/to/vulnerability-scanner && python vuln_scanner.py --target "Daily Scan" --hosts "example.com" --username "admin" --password "password" >> /var/log/vuln-scan.log 2>&1
   ```

3. For weekly scans:
   ```
   # Run vulnerability scan every Monday at 3 AM
   0 3 * * 1 cd /path/to/vulnerability-scanner && python vuln_scanner.py --target "Weekly Scan" --hosts "10.0.0.0/24" --username "admin" --password "password" >> /var/log/vuln-scan.log 2>&1
   ```

## Report Format

The scanner generates JSON reports with the following structure:

```json
{
  "timestamp": "2025-04-03T12:34:56.789012",
  "vulnerabilities": [
    {
      "name": "Vulnerability Name",
      "host": "192.168.1.1",
      "port": "80/tcp",
      "severity": 9.5
    },
    ...
  ]
}
```

## Security Considerations

- Store the configuration file securely as it contains credentials
- Consider using environment variables for sensitive data
- Run the scanner with the minimum required privileges
- Secure the reports directory to prevent unauthorized access

## Troubleshooting

### Common Issues

1. **Connection Error**:
   - Ensure the GVM service is running: `sudo gvm-check-setup`
   - Verify the socket path in the configuration file
   - Check permissions on the socket file

2. **Authentication Failed**:
   - Verify the GVM username and password
   - Ensure the user has sufficient permissions

3. **Scan Creation Failed**:
   - Verify that the IDs in the configuration file are correct
   - Check GVM logs for more details: `tail -f /var/log/gvm/gvmd.log`

4. **SMS Notifications Not Sending**:
   - Check the Twilio credentials in the configuration file
   - Verify that the Twilio account has sufficient funds
   - Check that the phone numbers are in the correct format (e.g., +12345678900)

## License

[MIT License](LICENSE)

## Acknowledgments

- This project uses [python-gvm](https://github.com/greenbone/python-gvm) for interacting with GVM
- SMS functionality provided by [Twilio](https://www.twilio.com/)
