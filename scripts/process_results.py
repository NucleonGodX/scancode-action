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
    parser.add_argument("--policy", help="Path to policy configuration file")
    parser.add_argument("--fail-on-findings", default="false", help="Fail if findings match policy criteria")
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


def extract_vulnerabilities(scan_results):
    """Extract vulnerabilities from scan results."""
    vulnerabilities = []
    
    # Check if vulnerabilities exist in scan results
    if 'extra_data' in scan_results and 'vulnerabilities' in scan_results['extra_data']:
        vulnerabilities = scan_results['extra_data']['vulnerabilities']
    
    return vulnerabilities


def check_license_policy(resources, policy):
    """Check resources against license policy."""
    if not policy or 'license' not in policy:
        return True, []
    
    violations = []
    license_policy = policy['license']
    allowed_licenses = license_policy.get('allowed', [])
    prohibited_licenses = license_policy.get('prohibited', [])
    min_clarity_score = license_policy.get('minimum_clarity_score', 0)
    
    for resource in resources['files']:
        if resource.get('path', '').endswith('policy.yml'):
            continue
        # Check if there are license detections in the file
        if 'detected_license_expression' not in resource or not resource['detected_license_expression']:
            continue
        
        # Get the detected license
        license_key = resource['detected_license_expression']
        
        # Check prohibited licenses
        if license_key in prohibited_licenses:
            violations.append({
                'type': 'prohibited_license',
                'license': license_key,
                'file_path': resource.get('path', ''),
                'message': f"Prohibited license '{license_key}' found in {resource.get('path', '')}"
            })
        
        # Check allowed licenses (if list is not empty)
        if allowed_licenses and license_key not in allowed_licenses:
            violations.append({
                'type': 'disallowed_license',
                'license': license_key,
                'file_path': resource.get('path', ''),
                'message': f"License '{license_key}' not in allowed list found in {resource.get('path', '')}"
            })
        
        # Check license clarity score from license detections if available
        if 'license_detections' in resource and resource['license_detections']:
            for detection in resource['license_detections']:
                if 'matches' in detection and detection['matches']:
                    for match in detection['matches']:
                        score = match.get('score', 0)
                        if score < min_clarity_score:
                            violations.append({
                                'type': 'low_clarity_score',
                                'license': license_key,
                                'score': score,
                                'file_path': resource.get('path', ''),
                                'message': f"License '{license_key}' has clarity score {score}, which is below minimum {min_clarity_score}"
                            })
    
    return len(violations) == 0, violations


def check_vulnerability_policy(vulnerabilities, policy):
    """Check vulnerabilities against policy."""
    if not policy or 'vulnerabilities' not in policy:
        return True, []
    
    violations = []
    vuln_policy = policy['vulnerabilities']
    max_severity = vuln_policy.get('maximum_severity', 'critical').lower()
    fail_on_unpatchable = vuln_policy.get('fail_on_unpatchable', False)
    
    # Map severity levels to numeric values for comparison
    severity_levels = {
        'none': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    max_severity_level = severity_levels.get(max_severity, 4)
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', '').lower()
        severity_level = severity_levels.get(severity, 0)
        
        # Check severity level
        if severity_level > max_severity_level:
            violations.append({
                'type': 'high_severity_vulnerability',
                'vulnerability_id': vuln.get('vulnerability_id', ''),
                'severity': severity,
                'package': vuln.get('package', {}).get('purl', ''),
                'message': f"Vulnerability {vuln.get('vulnerability_id', '')} has severity '{severity}' which exceeds maximum allowed '{max_severity}'"
            })
        
        # Check for unpatchable vulnerabilities
        if fail_on_unpatchable and not vuln.get('is_patchable', True):
            violations.append({
                'type': 'unpatchable_vulnerability',
                'vulnerability_id': vuln.get('vulnerability_id', ''),
                'severity': severity,
                'package': vuln.get('package', {}).get('purl', ''),
                'message': f"Unpatchable vulnerability {vuln.get('vulnerability_id', '')} found in {vuln.get('package', {}).get('purl', '')}"
            })
    
    return len(violations) == 0, violations



def main():
    """Main function."""
    args = parse_arguments()
    input_dir = os.path.dirname(args.input)
    results_files = [f for f in os.listdir(input_dir) if f.startswith("results-") and f.endswith(".json")]
    
    if not results_files:
        print(f"Error: No results file found in {input_dir}")
        sys.exit(1)
    
    results_file = os.path.join(input_dir, sorted(results_files)[-1])
    print(f"Using results file: {results_file}")

    scan_results = load_scan_results(results_file)
    
    # Load policy configuration if provided
    policy = load_policy(args.policy) if args.policy else None
    
    # Extract resources and vulnerabilities
    resources = extract_resources(scan_results)
    vulnerabilities = extract_vulnerabilities(scan_results)
    
    # Check against policies
    license_check_passed, license_violations = check_license_policy(resources, policy)
    vuln_check_passed, vuln_violations = check_vulnerability_policy(vulnerabilities, policy)
    
    if license_violations:
        print("\nLicense policy violations:")
        for violation in license_violations:
            print(f"  {violation['message']}")
    
    if vuln_violations:
        print("\nVulnerability policy violations:")
        for violation in vuln_violations:
            print(f"  {violation['message']}")
    
    # Determine exit code based on policy checks and fail-on-findings flag
    policy_passed = license_check_passed and vuln_check_passed
    if args.fail_on_findings.lower() == "true" and not policy_passed:
        print("\nPolicy violations found. Failing the workflow.")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()