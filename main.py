#!/usr/bin/env python3

import os
import sys
import json
import yaml
import argparse
from datetime import datetime
from twilio.rest import Client
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

def check_path_within_project(target_path):
    """
    Checks that target_path is located within the project root directory.
    If not, it prints an error message and exits the program.
    """
    project_root = os.path.dirname(os.path.abspath(__file__))
    target_abs = os.path.abspath(target_path)
    if os.path.commonpath([project_root, target_abs]) != project_root:
        print(f"Error: The path '{target_path}' is not within the permitted directory '{project_root}'.")
        sys.exit(1)

class VulnerabilityScanner:
    def __init__(self, config_path="./config.yml"):
        """
        Initialize the VulnerabilityScanner object.

        Parameters:
            config_path (str): Path to the YAML configuration file. Defaults to './config.yml'.
        """

        # Load config

        check_path_within_project(config_path)

        try:
            with open(config_path, 'r') as config_file:
                self.config = yaml.safe_load(config_file)
            print(f"Configuration loaded from {config_path}")
        except Exception as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)

        self.connection = UnixSocketConnection(path=self.config["gvm_socket_path"])
        self.transform = EtreeTransform()
        self.twilio_client = Client(
            self.config["twilio"]["account_sid"], 
            self.config["twilio"]["auth_token"]
        )

    def connect(self):
        """
        Connect to the GVM service using the configured socket path.

        Returns:
            bool: True if connection was successful, False otherwise.
        """

        try:
            self.gmp = Gmp(connection=self.connection, transform=self.transform)
            return True
        except Exception as e:
            print(f"Error connecting to GVM: {e}")
            return False

    def authenticate(self, username, password):
        """
        Authenticate with GVM using the provided credentials.

        Parameters:
            username (str): GVM username for authentication
            password (str): GVM password for authentication

        Returns:
            bool: True if authentication was successful, False otherwise.
        """

        try:
            with self.gmp:
                self.gmp.authenticate(username, password)
                return True
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False

    def create_target(self, name, hosts):
        """
        Create a scan target in GVM.

        Parameters:
            name (str): Name for the scan target
            hosts (str): Hosts to scan (IP addresses, ranges, or hostnames)

        Returns:
            str or None: Target ID if successful, None if failed.
        """

        try:
            with self.gmp:
                response = self.gmp.create_target(
                    name=name,
                    hosts=hosts,
                    port_list_id=self.config["port_list_id"]
                )
                target_id = response.get("id")
                print(f"Created target with ID: {target_id}")
                return target_id
        except Exception as e:
            print(f"Error creating target: {e}")
            return None

    def create_task(self, name, target_id):
        """
        Create a scan task in GVM.

        Parameters:
            name (str): Name for the scan task
            target_id (str): ID of the target to scan

        Returns:
            str or None: Task ID if successful, None if failed.
        """

        try:
            with self.gmp:
                response = self.gmp.create_task(
                    name=name,
                    config_id=self.config["scan_config_id"],
                    target_id=target_id,
                    scanner_id=self.config["scanner_id"]
                )
                task_id = response.get("id")
                print(f"Created task with ID: {task_id}")
                return task_id
        except Exception as e:
            print(f"Error creating task: {e}")
            return None

    def start_scan(self, task_id):
        """
        Start a vulnerability scan task.

        Parameters:
            task_id (str): ID of the task to start

        Returns:
            str or None: Report ID if scan started successfully, None if failed.
        """

        try:
            with self.gmp:
                response = self.gmp.start_task(task_id=task_id)
                report_id = response.get("report_id")
                print(f"Scan started with report ID: {report_id}")
                return report_id
        except Exception as e:
            print(f"Error starting scan: {e}")
            return None

    def get_task_status(self, task_id):
        """
        Get the current status of a task.

        Parameters:
            task_id (str): ID of the task to check

        Returns:
            str or None: Status string (e.g., "Running", "Done", "Failed") if successful, None if failed.
        """

        try:
            with self.gmp:
                response = self.gmp.get_task(task_id=task_id)
                status = response.xpath('//status/text()')[0]
                return status
        except Exception as e:
            print(f"Error getting task status: {e}")
            return None

    def wait_for_scan_completion(self, task_id, check_interval=30):
        """
        Wait for a scan to complete by periodically checking its status.

        Parameters:
            task_id (str): ID of the task to monitor
            check_interval (int): Interval in seconds between status checks. Defaults to 30.

        Returns:
            str: Final status of the task ("Done", "Stopped", or "Failed").
        """

        import time
        while True:
            status = self.get_task_status(task_id)
            if status in ["Done", "Stopped", "Failed"]:
                print(f"Scan completed with status: {status}")
                return status
            print(f"Scan in progress... Status: {status}")
            time.sleep(check_interval)

    def get_report(self, report_id):
        """
        Get a scan report from GVM.

        Parameters:
            report_id (str): ID of the report to retrieve

        Returns:
            Element or None: XML element containing the report if successful, None if failed.
        """

        try:
            with self.gmp:
                response = self.gmp.get_report(
                    report_id=report_id,
                    report_format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"  # (XML)
                )
                return response
        except Exception as e:
            print(f"Error getting report: {e}")
            return None

    def extract_critical_vulnerabilities(self, report):
        """
        Extract critical vulnerabilities from a report based on severity threshold.

        Parameters:
            report (Element): XML element containing the vulnerability report

        Returns:
            list: List of dictionaries containing critical vulnerability information.
                Each dictionary has keys: name, host, port, severity.
        """

        critical_vulns = []

        results = report.xpath('//result')
        for result in results:
            severity = float(result.xpath('severity/text()')[0])
            if severity >= self.config["severity_threshold"]:
                name = result.xpath('name/text()')[0]
                host = result.xpath('host/text()')[0]
                port = result.xpath('port/text()')[0]
                cvss_score = severity

                critical_vulns.append({
                    "name": name,
                    "host": host,
                    "port": port,
                    "severity": cvss_score
                })

        return critical_vulns

    def save_report(self, vulnerabilities, output_file):
        """
        Save vulnerabilities to a JSON file.

        Parameters:
            vulnerabilities (list): List of vulnerability dictionaries
            output_file (str): Path to save the output JSON file

        Returns:
            bool: True if report was saved successfully, False otherwise.
        """

        check_path_within_project(output_file)

        try:
            report_data = {
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": vulnerabilities
            }

            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=4)

            print(f"Report saved to {output_file}")
            return True
        except Exception as e:
            print(f"Error saving report: {e}")
            return False

    def send_sms_notification(self, vulnerabilities):
        """
        Send SMS notification for critical vulnerabilities using Twilio.

        Parameters:
            vulnerabilities (list): List of vulnerability dictionaries

        Returns:
            bool: True if SMS was sent successfully, False otherwise.
        """

        if not vulnerabilities:
            print("No critical vulnerabilities to report")
            return

        try:
            message_body = f"SECURITY ALERT: {len(vulnerabilities)} critical vulnerabilities detected!\n\n"

            # Add details for up to 3 vulnerabilities (to keep SMS reasonably sized)
            for i, vuln in enumerate(vulnerabilities[:3]):
                message_body += f"{i+1}. {vuln['name']} on {vuln['host']}:{vuln['port']} (CVSS: {vuln['severity']})\n"

            if len(vulnerabilities) > 3:
                message_body += f"... and {len(vulnerabilities) - 3} more. Check full report."

            message = self.twilio_client.messages.create(
                body=message_body,
                from_=self.config["twilio"]["from_number"],
                to=self.config["twilio"]["to_number"]
            )

            print(f"SMS notification sent. SID: {message.sid}")
            return True
        except Exception as e:
            print(f"Error sending SMS notification: {e}")
            return False

    def run_scan(self, target_name, hosts, output_dir="./reports"):
        """
        Run a complete vulnerability scan workflow from target creation to reporting.

        Parameters:
            target_name (str): Name for the scan target
            hosts (str): Hosts to scan (IP addresses, ranges, or hostnames)
            output_dir (str): Directory to save reports. Defaults to './reports'.

        Returns:
            bool: True if scan completed successfully, False otherwise.
        """

        print(f"Starting vulnerability scan for {hosts}")

        os.makedirs(output_dir, exist_ok=True)

        # Create target and task
        target_id = self.create_target(target_name, hosts)
        if not target_id:
            return False

        task_id = self.create_task(f"Scan of {target_name}", target_id)
        if not task_id:
            return False

        # Start scan and wait for completion
        report_id = self.start_scan(task_id)
        if not report_id:
            return False

        status = self.wait_for_scan_completion(task_id)
        if status != "Done":
            print(f"Scan failed with status: {status}")
            return False

        # Get and process results
        report = self.get_report(report_id)
        if not report:
            return False

        critical_vulns = self.extract_critical_vulnerabilities(report)
        print(f"Found {len(critical_vulns)} critical vulnerabilities")

        # Generate timestamp-based filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{output_dir}/{target_name}_{timestamp}.json"

        # Save report and send notification if critical vulnerabilities found
        self.save_report(critical_vulns, output_file)

        if critical_vulns:
            self.send_sms_notification(critical_vulns)

        return True

def main():
    """
    Main function to parse command line arguments and execute the vulnerability scan.

    Command line arguments:
        --config: Path to configuration file
        --target: Name of the scan target
        --hosts: Target hosts to scan
        --username: GVM username
        --password: GVM password
        --output-dir: Output directory for reports
    """

    parser = argparse.ArgumentParser(description='Vulnerability Scanner with SMS Notifications')
    parser.add_argument('--config', default='./config.yml', help='Path to configuration file')
    parser.add_argument('--target', required=True, help='Target name')
    parser.add_argument('--hosts', required=True, help='Target hosts (IP addresses, ranges, or hostnames)')
    parser.add_argument('--username', required=True, help='GVM username')
    parser.add_argument('--password', required=True, help='GVM password')
    parser.add_argument('--output-dir', default='./reports', help='Output directory for reports')

    args = parser.parse_args()

    scanner = VulnerabilityScanner(config_path=args.config)

    # Connect and authenticate
    if not scanner.connect():
        sys.exit(1)

    if not scanner.authenticate(args.username, args.password):
        sys.exit(1)

    # Run scan
    scanner.run_scan(args.target, args.hosts, args.output_dir)

if __name__ == "__main__":
    main()
