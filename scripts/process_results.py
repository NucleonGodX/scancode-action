import argparse
import json
import os
import sys
import yaml
from pathlib import Path


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Process ScanCode.io scan results")
    parser.add_argument("--input", required=True, help="Path to the ScanCode.io JSON output file")
    return parser.parse_args()


def load_scan_results(file_path):
    """Load and parse ScanCode.io JSON results."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading scan results: {e}")
        sys.exit(1)


def load_policy(file_path):
    """Load policy configuration from YAML file."""
    if not file_path or not os.path.exists(file_path):
        return None
    
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except (IOError, yaml.YAMLError) as e:
        print(f"Error loading policy file: {e}")
        return None


def extract_resources(scan_results):
    """Extract resources (packages, dependencies, files) from scan results."""
    resources = {
        'packages': scan_results.get('packages', []),
        'dependencies': scan_results.get('dependencies', []),
        'files': scan_results.get('files', [])
    }
    
    return resources
